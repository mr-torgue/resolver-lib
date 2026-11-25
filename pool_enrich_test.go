package resolver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// Regression test: enrich() must accept A records for a hostname that already
// had its AAAA records added (and vice versa). The A and AAAA enrichment
// queries for a zone's nameservers run concurrently, so either family can
// arrive first. The pool must never end up single-family: a zone with only
// IPv6 nameservers cannot be resolved on a host without IPv6 connectivity.
func TestPoolEnrich_BothFamiliesRegardlessOfArrivalOrder(t *testing.T) {
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
	}

	aaaa := &dns.AAAA{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeAAAA, Ttl: 300}, AAAA: net.ParseIP("2001:db8::1")}
	a := &dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")}

	t.Run("AAAA first", func(t *testing.T) {
		pool := newNameserverPool(nameservers, nil, ConfigBuilder())
		assert.Len(t, pool.hostsWithoutAddresses, 1)

		pool.enrich([]dns.RR{aaaa})
		assert.Equal(t, uint32(1), pool.countIPv6())
		assert.Empty(t, pool.hostsWithoutAddresses)

		// The A response arrives after the hostname was already removed from
		// the pending list: it must still be added.
		pool.enrich([]dns.RR{a})
		assert.Equal(t, uint32(1), pool.countIPv4(), "A records must be added even when AAAA was enriched first")
		assert.Equal(t, uint32(1), pool.countIPv6())
	})

	t.Run("A first", func(t *testing.T) {
		pool := newNameserverPool(nameservers, nil, ConfigBuilder())

		pool.enrich([]dns.RR{a})
		assert.Equal(t, uint32(1), pool.countIPv4())
		assert.Empty(t, pool.hostsWithoutAddresses)

		pool.enrich([]dns.RR{aaaa})
		assert.Equal(t, uint32(1), pool.countIPv6(), "AAAA records must be added even when A was enriched first")
	})
}

// A nameserver that arrived with glue A records must still receive its AAAA
// records from enrichment, so the pool has both families for it.
func TestPoolEnrich_MissingFamilyForGluedHostname(t *testing.T) {
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
	}
	extra := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
	}

	pool := newNameserverPool(nameservers, extra, ConfigBuilder())
	assert.Equal(t, uint32(1), pool.countIPv4())
	assert.Equal(t, uint32(0), pool.countIPv6())

	pool.enrich([]dns.RR{
		&dns.AAAA{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeAAAA, Ttl: 300}, AAAA: net.ParseIP("2001:db8::1")},
	})

	assert.Equal(t, uint32(1), pool.countIPv6(), "AAAA records must be enriched for a hostname that had glue A records")
	assert.Equal(t, uint32(1), pool.countIPv4())
}

// Records for hostnames that are not nameservers of this zone must be ignored.
func TestPoolEnrich_IgnoresUnknownHostnames(t *testing.T) {
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
	}

	pool := newNameserverPool(nameservers, nil, ConfigBuilder())

	pool.enrich([]dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "unrelated.example.org.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.99")},
	})

	assert.Equal(t, uint32(0), pool.countIPv4())
	assert.Equal(t, uint32(0), pool.countIPv6())
	assert.Len(t, pool.hostsWithoutAddresses, 1, "the pending hostname must remain pending")
}

// enrich() must not duplicate addresses, even if the same records are fed in twice.
func TestPoolEnrich_DoesNotDuplicateAddresses(t *testing.T) {
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
	}

	pool := newNameserverPool(nameservers, nil, ConfigBuilder())
	records := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
	}

	pool.enrich(records)
	pool.enrich(records)

	assert.Equal(t, uint32(1), pool.countIPv4())
}
