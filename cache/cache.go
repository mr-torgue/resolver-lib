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
	ErrCacheMiss    = fmt.Errorf("Cache entry not found")
	ErrCacheExpired = fmt.Errorf("Cache entry expired")
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

func Key(name string, qtype uint16) uint64 {
	h := fnv.New64a()
	h.Write([]byte(dns.CanonicalName(name)))
	h.Write([]byte(dns.TypeToString[qtype]))
	return h.Sum64()
}

func (c *Cache) Update(zone string, question dns.Question, msg *dns.Msg) error {
	// Group records by RRSet (Name + Type)
	// We combine Answer, Ns, and Extra sections
	allRRs := append(append(msg.Answer, msg.Ns...), msg.Extra...)
	rrsets := make(map[uint64][]dns.RR)
	sigs := make(map[uint64][]dns.RR)

	for _, rr := range allRRs {
		h := rr.Header()
		if h.Rrtype == dns.TypeRRSIG {
			sig := rr.(*dns.RRSIG)
			k := Key(h.Name, sig.TypeCovered)
			sigs[k] = append(sigs[k], rr)
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
			Expires:    time.Now().Add(time.Duration(h.Ttl) * time.Second),
		}
		c.cache.Add(k, entry)
	}

	return nil
}

// Get returns an item from cache.
func (c *Cache) Get(zone string, question dns.Question) (*dns.Msg, error) {
	// always return a message
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeServerFailure

	key := Key(question.Name, question.Qtype)

	val, ok := c.cache.Get(key)
	if val == nil || !ok {
		return msg, ErrCacheMiss
	}

	if time.Now().After(val.Expires) {
		c.cache.Remove(key)
		return msg, ErrCacheExpired
	}

	// Construct response message
	msg.Answer = append(val.Records, val.Signatures...)
	msg.Rcode = val.Rcode

	// Set AD bit if Secure
	if val.Status == Secure {
		msg.AuthenticatedData = true
	}
	return msg, nil
}
