package resolver

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/mr-torgue/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newConcurrentTestResolver builds a real Resolver (root zone + anchors from testdata),
// but with the label resolution mocked out, so no network access is needed.
// answerIP lets each resolver return a distinguishable answer.
func newConcurrentTestResolver(t *testing.T, answerIP string, options ...Option) *Resolver {
	t.Helper()

	options = append([]Option{
		WithCustomRoot("testdata/rootzones/named.root", "testdata/rootanchors/root-anchors.xml"),
	}, options...)

	r := NewResolver(ConfigBuilder(options...))
	require.NotNil(t, r)

	qname := "www.example.com."
	answer := &dns.A{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP(answerIP),
	}

	r.funcs.resolveLabel = func(ctx context.Context, d *domain, z zone, qmsg *dns.Msg, auth *authenticator) (zone, *Response) {
		rmsg := qmsg.SetReply(qmsg)
		rmsg.Answer = []dns.RR{answer}
		return nil, &Response{Msg: rmsg}
	}
	r.funcs.getExchanger = func() exchanger { return r }

	return r
}

// TestTwoResolvers_ConcurrentExchange runs two independent Resolver instances side by side
// (like multiple `resolver {}` blocks in one CoreDNS server) and hammers both with
// concurrent queries. Each resolver must only ever see its own answers.
func TestTwoResolvers_ConcurrentExchange(t *testing.T) {
	r1 := newConcurrentTestResolver(t, "192.0.2.1", WithClient("udp", true), WithCache(64))
	r2 := newConcurrentTestResolver(t, "192.0.2.2", WithClient("tcp", false), WithCache(128))

	const workers = 8
	const queriesPerWorker = 25

	run := func(r *Resolver, ip string, wg *sync.WaitGroup) {
		defer wg.Done()
		for i := 0; i < queriesPerWorker; i++ {
			qmsg := new(dns.Msg)
			qmsg.SetQuestion("www.example.com.", dns.TypeA)

			response := r.Exchange(context.Background(), qmsg)
			require.NotNil(t, response)
			require.False(t, response.HasError(), "resolver for %s returned error: %v", ip, response.Err)
			require.Len(t, response.Msg.Answer, 1)
			a, ok := response.Msg.Answer[0].(*dns.A)
			require.True(t, ok)
			assert.Equal(t, ip, a.A.String(), "resolver cross-talk detected: expected %s", ip)
		}
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(2)
		go run(r1, "192.0.2.1", &wg)
		go run(r2, "192.0.2.2", &wg)
	}
	wg.Wait()

	// Each resolver has its own zone store, holding only the root zone.
	assert.Equal(t, 1, r1.CountZones())
	assert.Equal(t, 1, r2.CountZones())
	assert.NotSame(t, r1.zones, r2.zones)
	assert.NotSame(t, r1.config, r2.config)
}

// TestNewResolver_ConcurrentConstruction creates many resolvers at the same time.
// NewResolver loads the DNSSEC trust anchors into a package-level variable, so this
// exercises whether concurrent construction is safe (run with -race).
func TestNewResolver_ConcurrentConstruction(t *testing.T) {
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
		// Each instance carries its own trust anchors; no shared global is written.
		assert.NotEmpty(t, r.config.trustAnchors, "resolver %d should have its own trust anchors", i)
	}
}

// TestTwoResolvers_ConcurrentZoneCreation has two resolvers create child zones
// (with pool enrichment) at the same time. The zones must land in separate stores.
func TestTwoResolvers_ConcurrentZoneCreation(t *testing.T) {
	newMockExchanger := func() *mockExchanger {
		return &mockExchanger{
			mockExchange: func(ctx context.Context, qmsg *dns.Msg) *Response {
				rmsg := qmsg.SetReply(qmsg)
				rmsg.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: qmsg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.ParseIP("192.0.2.53"),
					},
				}
				return &Response{Msg: rmsg}
			},
		}
	}

	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
	}

	configs := []*Config{ConfigBuilder(), ConfigBuilder(WithClient("tcp", false))}
	exchangers := []exchanger{newMockExchanger(), newMockExchanger()}
	zonesOut := make([]zone, 2)
	errs := make([]error, 2)

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			zonesOut[i], errs[i] = createZone(context.Background(), "example.com.", ".", nameservers, nil, exchangers[i], configs[i])
		}(i)
	}
	wg.Wait()

	for i := 0; i < 2; i++ {
		require.NoError(t, errs[i])
		require.NotNil(t, zonesOut[i])
		assert.Equal(t, "example.com.", zonesOut[i].name())
	}
	assert.NotSame(t, zonesOut[0], zonesOut[1])
}

// TestNameserverPool_ConcurrentEnrich hammers one pool with concurrent enrichment,
// status checks and address lookups, mimicking several queries hitting a freshly
// delegated zone at once (run with -race).
func TestNameserverPool_ConcurrentEnrich(t *testing.T) {
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
	}

	pool := newNameserverPool(nameservers, nil, ConfigBuilder())
	require.Equal(t, PoolHasHostnamesButNoIpAddresses, pool.status())

	exchanger := &mockExchanger{
		mockExchange: func(ctx context.Context, qmsg *dns.Msg) *Response {
			rmsg := qmsg.SetReply(qmsg)
			rmsg.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: qmsg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.53"),
				},
			}
			return &Response{Msg: rmsg}
		},
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_ = enrichPool(context.Background(), "example.com.", pool, exchanger, ConfigBuilder())
			} else {
				for j := 0; j < 50; j++ {
					_ = pool.status()
					_ = pool.getIPv4()
				}
			}
		}(i)
	}
	wg.Wait()

	assert.True(t, pool.hasIPv4())
	assert.Equal(t, PoolPrimed, pool.status())
}

// TestInstances_IndependentConfig verifies that two resolvers built with different
// per-instance options behave independently, and that mutating the package-level
// default variables afterwards does not affect already-built resolvers.
func TestInstances_IndependentConfig(t *testing.T) {
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
	}
	extra := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
	}
	workingExchanger := &mockExchanger{
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

	// Two would-be resolvers with different lazyEnrichment settings.
	// With one primed IP but < desireNumberOfNameserversPerZone, a pool is PrimedButNeedsEnhancing,
	// and createZone only enriches in the background when lazyEnrichment is false.
	z1, err1 := createZone(context.Background(), "example.com.", ".", nameservers, extra, workingExchanger, ConfigBuilder(WithLazyEnrichment(false)))
	z2, err2 := createZone(context.Background(), "example.com.", ".", nameservers, extra, workingExchanger, ConfigBuilder(WithLazyEnrichment(true)))

	require.NoError(t, err1)
	require.NoError(t, err2)
	require.NotNil(t, z1)
	require.NotNil(t, z2)

	// Mutating the package-level default afterwards must not change existing instances.
	defer func() { LazyEnrichment = DefaultLazyEnrichment }()
	LazyEnrichment = true

	pool2 := z2.(*zoneImpl).pool.(*nameserverPool)
	assert.Equal(t, PrimedButNeedsEnhancing, pool2.status())
	assert.False(t, z1.(*zoneImpl).config.lazyEnrichment == z2.(*zoneImpl).config.lazyEnrichment)

	fmt.Println("each resolver keeps its own lazyEnrichment setting")
}
