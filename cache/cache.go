package cache

import (
	"fmt"
	"hash/fnv"
	"time"

	"github.com/mr-torgue/coredns/plugin/pkg/cache"
	"github.com/mr-torgue/dns"
)

type ValidationStatus int

var (
	ErrEmptyQuestion    = fmt.Errorf("Question is empty")
	ErrCacheMiss        = fmt.Errorf("Cache entry not found")
	ErrCacheExpired     = fmt.Errorf("Cache entry expired")
	ErrCacheNoTruncated = fmt.Errorf("Cache does not cache truncated messages")
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

// UpdateWithTime inserts a dns message into the cache.
// It splits the message into resource records for better granularity.
func (c *Cache) UpdateWithTime(zone string, question dns.Question, msg *dns.Msg, now time.Time) error {
	// Group records by RRSet (Name + Type)
	// We combine Answer, Ns, and Extra sections
	allRRs := append(append(msg.Answer, msg.Ns...), msg.Extra...)
	rrsets := make(map[uint64][]dns.RR)
	sigs := make(map[uint64][]dns.RR)

	if msg.Truncated {
		return ErrCacheNoTruncated
	}

	for _, rr := range allRRs {
		h := rr.Header()
		if h.Rrtype == dns.TypeRRSIG {
			sig := rr.(*dns.RRSIG)
			k := Key(h.Name, sig.TypeCovered)
			// check validity
			if sig.ValidityPeriod(now) {
				sigs[k] = append(sigs[k], rr)
			} else {
				sigs[k] = []dns.RR{}
			}
		} else if h.Rrtype == dns.TypeOPT || h.Rrtype == dns.TypeTSIG || h.Rrtype == dns.TypeIXFR || h.Rrtype == dns.TypeAXFR || h.Rrtype == dns.TypeMAILB || h.Rrtype == dns.TypeMAILA || h.Rrtype == dns.TypeANY {
			// ignore these RR's
			continue
		} else {
			k := Key(h.Name, h.Rrtype)
			rrsets[k] = append(rrsets[k], rr)
		}
	}

	// Cache each RRSet
	for k, records := range rrsets {
		// check if sigs[k] is empty slice: indicates that there was an RRSIG, but it was invalid
		if len(sigs[k]) != 0 || sigs[k] == nil {
			// Determine Security Status
			status := Indeterminate

			h := records[0].Header()
			entry := &Entry{
				Name:       h.Name,
				Type:       h.Rrtype,
				Status:     status,
				Records:    records,
				Signatures: sigs[k],
				TTL:        h.Ttl,
				Expires:    now.Add(time.Duration(h.Ttl) * time.Second),
			}
			c.cache.Add(k, entry)
		}
	}
	return nil
}

// Update uses time.now() for convenience.
func (c *Cache) Update(zone string, question dns.Question, msg *dns.Msg) error {
	return c.UpdateWithTime(zone, question, msg, time.Now())
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

	if now.After(val.Expires) {
		c.cache.Remove(key)
		return msg, ErrCacheExpired
	}

	// Construct response message
	msg.Answer = append(val.Records, val.Signatures...)
	msg.Rcode = val.Rcode
	msg.SetReply(qmsg)

	// set opt record if qmsg had one
	edns0 := qmsg.IsEdns0()
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
		fmt.Printf("Key: %d, Name: %s, Type: %d, Status: %d, TTL: %d, Expires: %v\n",
			key, entry.Name, entry.Type, entry.Status, entry.TTL, entry.Expires)
		count++
		return true
	})
	return count
}
