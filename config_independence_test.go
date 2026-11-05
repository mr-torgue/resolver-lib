package resolver

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/mr-torgue/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigBuilder_InstancesAreIndependent verifies that two Configs built with
// different options keep their own values, and that mutating the package-level
// default variables afterwards does not affect already-built Configs.
func TestConfigBuilder_InstancesAreIndependent(t *testing.T) {
	c1 := ConfigBuilder(WithLazyEnrichment(false), WithMaxQueriesPerRequest(2), WithMaxAllowedTTL(60))
	c2 := ConfigBuilder(WithLazyEnrichment(true), WithMaxQueriesPerRequest(50), WithMaxAllowedTTL(3600))

	defer func() {
		LazyEnrichment = DefaultLazyEnrichment
		MaxQueriesPerRequest = DefaultMaxQueriesPerRequest
		MaxAllowedTTL = DefaultMaxAllowedTTL
	}()

	// Mutate the package-level defaults after both configs were built.
	LazyEnrichment = true
	MaxQueriesPerRequest = 1
	MaxAllowedTTL = 1

	assert.False(t, c1.lazyEnrichment)
	assert.True(t, c2.lazyEnrichment)
	assert.Equal(t, uint32(2), c1.maxQueriesPerRequest)
	assert.Equal(t, uint32(50), c2.maxQueriesPerRequest)
	assert.Equal(t, uint32(60), c1.maxAllowedTTL)
	assert.Equal(t, uint32(3600), c2.maxAllowedTTL)
}

// TestNewResolver_ConcurrentConstruction_IndependentAnchors creates many resolvers
// at the same time; each must get its own trust anchors without any shared global write.
func TestNewResolver_ConcurrentConstruction_IndependentAnchors(t *testing.T) {
	const n = 16

	resolvers := make([]*Resolver, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resolvers[i] = NewResolver(ConfigBuilder(
				WithCustomRoot("testdata/rootzones/named.root", "testdata/rootanchors/root-anchors.xml"),
			))
		}(i)
	}
	wg.Wait()

	for i, r := range resolvers {
		require.NotNil(t, r, "resolver %d", i)
		assert.Equal(t, 1, r.CountZones(), "resolver %d should have only the root zone", i)
		assert.NotEmpty(t, r.config.trustAnchors, "resolver %d should have its own trust anchors", i)
	}
}

// TestCreateZone_PerInstanceLazyEnrichment shows two zones created with different
// per-instance lazyEnrichment settings behave independently.
func TestCreateZone_PerInstanceLazyEnrichment(t *testing.T) {
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
	}
	extra := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
	}
	exchanger := &mockExchanger{
		mockExchange: func(ctx context.Context, qmsg *dns.Msg) *Response {
			rmsg := qmsg.SetReply(qmsg)
			rmsg.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: qmsg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.54"),
				},
			}
			return &Response{Msg: rmsg}
		},
	}

	z1, err1 := createZone(context.Background(), "example.com.", ".", nameservers, extra, exchanger, ConfigBuilder(WithLazyEnrichment(false)))
	z2, err2 := createZone(context.Background(), "example.com.", ".", nameservers, extra, exchanger, ConfigBuilder(WithLazyEnrichment(true)))

	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.False(t, z1.(*zoneImpl).config.lazyEnrichment)
	assert.True(t, z2.(*zoneImpl).config.lazyEnrichment)

	pool2 := z2.(*zoneImpl).pool.(*nameserverPool)
	assert.Equal(t, PrimedButNeedsEnhancing, pool2.status())
}
