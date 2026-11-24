package cache

import (
	"fmt"
	"hash/fnv"
	"time"

	"github.com/coredns/coredns/plugin/pkg/cache"
	"github.com/miekg/dns"
)

type ValidationStatus int

var (
	ErrEmptyQuestion    = fmt.Errorf("question is empty")
	ErrCacheMiss        = fmt.Errorf("cache entry not found")
	ErrCacheExpired     = fmt.Errorf("cache entry expired")
	ErrCacheNoTruncated = fmt.Errorf("cache does not cache truncated messages")
	ErrNotValidated     = fmt.Errorf("cache entry found, but not validated yet")
	DefaultCapacity     = 1000
)

// rename this so it starts with DNSSEC
const (
	Indeterminate ValidationStatus = iota
	Secure
	Insecure
	Bogus
)

type Cache struct {
	cache    *cache.Cache[*Entry]
	capacity int
}

type Entry struct {
	Name       string
	Type       uint16
	Status     ValidationStatus
	Rcode      int
	Negative   bool // entry holds a negative answer (authority records, no answer)
	Records    []dns.RR
	Signatures []dns.RR
	TTL        uint32
	Expires    time.Time
}

// Key returns a cache key, which is defined as hash(qname + qtype).
func Key(name string, qtype uint16) uint64 {
	h := fnv.New64a()
	h.Write([]byte(dns.CanonicalName(name)))
	h.Write([]byte(dns.TypeToString[qtype]))
	return h.Sum64()
}

// Cache options
type Option func(*Cache)

func WithCapacity(capacity int) Option {
	return func(c *Cache) {
		c.capacity = capacity
	}
}

// NewCache initializes and returns a new cache instance.
func NewCache(options ...Option) *Cache {
	// set default values
	c := &Cache{
		capacity: DefaultCapacity,
	}
	// parse options
	for _, o := range options {
		o(c)
	}
	c.cache = cache.New[*Entry](c.capacity)
	return c
}

// ignoredType reports whether RRs of this type are never cached.
func ignoredType(t uint16) bool {
	switch t {
	case dns.TypeOPT, dns.TypeTSIG, dns.TypeIXFR, dns.TypeAXFR, dns.TypeMAILB, dns.TypeMAILA, dns.TypeANY:
		return true
	}
	return false
}

// sectionRRs returns a fresh slice with all RRs from the answer, authority and
// additional sections. It never aliases the backing arrays of msg's sections.
func sectionRRs(msg *dns.Msg) []dns.RR {
	all := make([]dns.RR, 0, len(msg.Answer)+len(msg.Ns)+len(msg.Extra))
	all = append(all, msg.Answer...)
	all = append(all, msg.Ns...)
	all = append(all, msg.Extra...)
	return all
}

// splitRRsets groups the RRs of msg by RRset key (name + type). Signatures are
// grouped by the key of the RRset they cover and deep-copied. RRsets whose
// signature is expired at now are reported in badSigs and must not be cached.
func splitRRsets(msg *dns.Msg, now time.Time) (rrsets map[uint64][]dns.RR, sigs map[uint64][]dns.RR, badSigs map[uint64]bool) {
	rrsets = make(map[uint64][]dns.RR)
	sigs = make(map[uint64][]dns.RR)
	badSigs = make(map[uint64]bool)
	for _, rr := range sectionRRs(msg) {
		h := rr.Header()
		if h.Rrtype == dns.TypeRRSIG {
			sig := rr.(*dns.RRSIG)
			k := Key(h.Name, sig.TypeCovered)
			if sig.ValidityPeriod(now) {
				sigs[k] = append(sigs[k], dns.Copy(rr))
			} else {
				badSigs[k] = true
			}
			continue
		}
		if ignoredType(h.Rrtype) {
			continue
		}
		k := Key(h.Name, h.Rrtype)
		rrsets[k] = append(rrsets[k], dns.Copy(rr))
	}
	return rrsets, sigs, badSigs
}

// minTTL returns the smallest TTL found in the given record sets, or 0 if all
// sets are empty.
func minTTL(sets ...[]dns.RR) uint32 {
	ttl := uint32(0)
	seen := false
	for _, set := range sets {
		for _, rr := range set {
			if !seen || rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
				seen = true
			}
		}
	}
	if !seen {
		return 0
	}
	return ttl
}

// addEntry inserts an entry into the cache. An unvalidated insert never
// overwrites a validated, non-expired entry.
func (c *Cache) addEntry(k uint64, name string, rrtype uint16, records, signatures []dns.RR, rcode int, negative bool, ttl uint32, status ValidationStatus, now time.Time) {
	if ttl == 0 {
		return
	}
	if status == Indeterminate {
		if existing, ok := c.cache.Get(k); ok && existing != nil && existing.Status != Indeterminate && now.Before(existing.Expires) {
			return
		}
	}
	c.cache.Add(k, &Entry{
		Name:       name,
		Type:       rrtype,
		Status:     status,
		Rcode:      rcode,
		Negative:   negative,
		Records:    records,
		Signatures: signatures,
		TTL:        ttl,
		Expires:    now.Add(time.Duration(ttl) * time.Second),
	})
}

// UpdateWithTime inserts a dns message into the cache as Indeterminate
// (pending validation). It splits the message into resource records for better
// granularity. Negative responses (NXDOMAIN / NODATA) are cached under the
// question key. Call UpdateValidationWithTime once the message has been
// validated to mark the entries Secure, Insecure or Bogus.
func (c *Cache) UpdateWithTime(zone string, question dns.Question, msg *dns.Msg, now time.Time) error {
	if msg == nil || len(msg.Question) == 0 {
		return ErrEmptyQuestion
	}
	if msg.Truncated {
		return ErrCacheNoTruncated
	}

	rrsets, sigs, badSigs := splitRRsets(msg, now)

	// Cache each RRSet
	for k, records := range rrsets {
		if badSigs[k] {
			// There was an RRSIG covering this RRset, but it is expired: don't cache it.
			continue
		}
		h := records[0].Header()
		c.addEntry(k, h.Name, h.Rrtype, records, sigs[k], msg.Rcode, false, minTTL(records, sigs[k]), Indeterminate, now)
	}

	// Negative caching: cache NXDOMAIN / NODATA responses under the question
	// key so a repeated question can be answered from cache. Referrals
	// (NOERROR without answers and without a SOA) are deliberately not cached
	// under the question key: the resolver must keep querying the next zone.
	hasSOA := false
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == dns.TypeSOA {
			hasSOA = true
			break
		}
	}
	if msg.Rcode != dns.RcodeSuccess || (len(msg.Answer) == 0 && hasSOA) {
		auth := make([]dns.RR, 0, len(msg.Ns))
		authSigs := make([]dns.RR, 0)
		for _, rr := range msg.Ns {
			h := rr.Header()
			if h.Rrtype == dns.TypeRRSIG {
				if rr.(*dns.RRSIG).ValidityPeriod(now) {
					authSigs = append(authSigs, dns.Copy(rr))
				}
				continue
			}
			if ignoredType(h.Rrtype) {
				continue
			}
			auth = append(auth, dns.Copy(rr))
		}
		if len(auth) > 0 {
			c.addEntry(Key(question.Name, question.Qtype), question.Name, question.Qtype, auth, authSigs, msg.Rcode, true, minTTL(auth, authSigs), Indeterminate, now)
		}
	}
	return nil
}

// Update uses time.now() for convenience.
func (c *Cache) Update(zone string, question dns.Question, msg *dns.Msg) error {
	return c.UpdateWithTime(zone, question, msg, time.Now())
}

// UpdateValidationWithTime records the validation outcome for the cache entry
// of the question and for every RRset entry that makes up msg. Bogus entries
// are removed: bogus data must never be served from the cache.
func (c *Cache) UpdateValidationWithTime(zone string, question dns.Question, msg *dns.Msg, status ValidationStatus, now time.Time) error {
	if question.Name == "" {
		return ErrEmptyQuestion
	}
	keys := map[uint64]bool{Key(question.Name, question.Qtype): true}
	if msg != nil {
		for _, rr := range sectionRRs(msg) {
			h := rr.Header()
			if h.Rrtype == dns.TypeRRSIG {
				keys[Key(h.Name, rr.(*dns.RRSIG).TypeCovered)] = true
			} else if !ignoredType(h.Rrtype) {
				keys[Key(h.Name, h.Rrtype)] = true
			}
		}
	}
	for k := range keys {
		if status == Bogus {
			c.cache.Remove(k)
			continue
		}
		if val, ok := c.cache.Get(k); ok && val != nil {
			updated := *val
			updated.Status = status
			c.cache.Add(k, &updated)
		}
	}
	return nil
}

// UpdateValidation uses time.now() for convenience.
func (c *Cache) UpdateValidation(zone string, question dns.Question, msg *dns.Msg, status ValidationStatus) error {
	return c.UpdateValidationWithTime(zone, question, msg, status, time.Now())
}

// copyRRs returns deep copies of rrs with each TTL decremented by elapsed
// seconds, so that callers can never mutate the records held by a cache entry.
func copyRRs(rrs []dns.RR, elapsed uint32) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		cp := dns.Copy(rr)
		ttl := rr.Header().Ttl
		if ttl > elapsed {
			cp.Header().Ttl = ttl - elapsed
		} else {
			cp.Header().Ttl = 0
		}
		out[i] = cp
	}
	return out
}

// Get returns an item from cache.
func (c *Cache) GetWithTime(zone string, qmsg *dns.Msg, now time.Time) (*dns.Msg, error) {
	if qmsg == nil || len(qmsg.Question) == 0 {
		return nil, ErrEmptyQuestion
	}
	// always return a message
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeServerFailure
	question := qmsg.Question[0]

	key := Key(question.Name, question.Qtype)

	val, ok := c.cache.Get(key)
	if val == nil || !ok {
		return msg, ErrCacheMiss
	}

	// The key is only a 64-bit hash: verify the entry really belongs to this
	// question before using it.
	if dns.CanonicalName(val.Name) != dns.CanonicalName(question.Name) || val.Type != question.Qtype {
		return msg, ErrCacheMiss
	}

	if now.After(val.Expires) {
		c.cache.Remove(key)
		return msg, ErrCacheExpired
	}

	// Trust gate: never serve Bogus entries, and never serve unvalidated
	// entries to clients that asked for validation (DO=1 without CD).
	if val.Status == Bogus {
		return msg, ErrCacheMiss
	}
	edns0 := qmsg.IsEdns0()
	if val.Status == Indeterminate && edns0 != nil && edns0.Do() && !qmsg.CheckingDisabled {
		return msg, ErrNotValidated
	}

	// Decrement the TTLs by the time the entry has already been cached.
	inserted := val.Expires.Add(-time.Duration(val.TTL) * time.Second)
	elapsed := uint32(0)
	if d := now.Sub(inserted); d > 0 {
		elapsed = uint32(d / time.Second)
	}

	// Construct response message
	msg.SetReply(qmsg)
	msg.Rcode = val.Rcode
	if val.Negative {
		msg.Ns = append(copyRRs(val.Records, elapsed), copyRRs(val.Signatures, elapsed)...)
	} else {
		msg.Answer = append(copyRRs(val.Records, elapsed), copyRRs(val.Signatures, elapsed)...)
	}

	// set opt record if qmsg had one
	if edns0 != nil {
		msg.SetEdns0(edns0.UDPSize(), edns0.Do())
	}

	msg.Authoritative = true // according to tests: "Cache entries are always Authoritative"

	// Set AD bit if Secure
	if val.Status == Secure {
		msg.AuthenticatedData = true
	}
	return msg, nil
}

// Get returns an item from cache.
func (c *Cache) Get(zone string, qmsg *dns.Msg) (*dns.Msg, error) {
	return c.GetWithTime(zone, qmsg, time.Now())
}

// Len returns the cache length.
func (c *Cache) Len() int {
	return c.cache.Len()
}

// Print is a debug function that prints all items in the cache.
func (c *Cache) Print() int {
	count := 0
	c.cache.Walk(func(entries map[uint64]*Entry, key uint64) bool {
		entry := entries[key]
		fmt.Printf("Key: %d, Name: %s, Type: %d, Status: %d, Rcode: %d, TTL: %d, Expires: %v\n",
			key, entry.Name, entry.Type, entry.Status, entry.Rcode, entry.TTL, entry.Expires)
		count++
		return true
	})
	return count
}
