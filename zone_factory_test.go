package resolver

import (
	"context"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCreateZone_SuccessWithoutEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers and extra records. A primed pool is, by default, >= 3 nameservers with glue records.
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
		{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeNS}, Ns: "ns3.example.com."},
	}
	extra := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
		&dns.A{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.54")},
		&dns.A{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.55")},
	}
	ctx := context.TODO()

	// Execute
	z, err := createZone(ctx, context.Background(), "example.com.", "com.", nameservers, extra, mockExchanger, ConfigBuilder()) // default config

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, z)
	assert.Equal(t, "example.com.", z.name())

	// We'll peek under the covers to ensure the pool was created as expected.
	pool, ok := z.(*zoneImpl).pool.(*nameserverPool)
	assert.True(t, ok)
	assert.Equal(t, pool.status(), PoolPrimed)
}

func TestCreateZone_PoolCreationFailsWithoutEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers with no valid addresses
	nameservers := []*dns.NS{}
	extra := []dns.RR{}
	ctx := context.TODO()

	// Execute
	z, err := createZone(ctx, context.Background(), "example.com.", "com.", nameservers, extra, mockExchanger, ConfigBuilder()) // default config

	// Assertions
	assert.Nil(t, z)
	assert.ErrorIs(t, err, ErrFailedCreatingZoneAndPool)
}

func TestCreateZone_SuccessWithEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers and extra records
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
		{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeNS}, Ns: "ns3.example.com."},
	}
	extra := []dns.RR{}
	ctx := context.TODO()

	// Mock the exchanger behavior if needed (e.g., to enrich the pool)
	mockExchanger.On("exchange", mock.Anything, mock.Anything).Return(&Response{
		Msg: &dns.Msg{
			Answer: []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
				&dns.A{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.54")},
				&dns.A{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.55")},
			},
		},
		Duration: 10 * time.Millisecond,
	})

	// Execute
	z, err := createZone(ctx, context.Background(), "example.com.", "com.", nameservers, extra, mockExchanger, ConfigBuilder()) // default config

	// AssertionsOk
	assert.NoError(t, err)
	assert.NotNil(t, z)
	assert.Equal(t, "example.com.", z.name())

	// We'll peek under the covers to ensure the pool was created as expected.
	pool, ok := z.(*zoneImpl).pool.(*nameserverPool)
	assert.True(t, ok)
	assert.Equal(t, pool.status(), PoolPrimed)
}

func TestCreateZone_PoolCreationFailsWithEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers and extra records
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
		{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeNS}, Ns: "ns3.example.com."},
	}
	extra := []dns.RR{}
	ctx := context.TODO()

	// Mock the exchanger behavior if needed (e.g., to enrich the pool)
	mockExchanger.On("exchange", mock.Anything, mock.Anything).Return(&Response{
		Msg: &dns.Msg{
			Answer: []dns.RR{},
		},
		Duration: 10 * time.Millisecond,
	})

	// Execute
	z, err := createZone(ctx, context.Background(), "example.com.", "com.", nameservers, extra, mockExchanger, ConfigBuilder()) // default config

	// Assertions
	assert.Nil(t, z)
	assert.ErrorIs(t, err, ErrFailedEnrichingPool)
}

// TestCreateZone_SuccessWithOptionalEnrichment Has one glue record returned, so tried to enrich to find the addresses of the other two.
func TestCreateZone_SuccessWithOptionalEnrichment(t *testing.T) {
	// Setup
	mockExchanger := new(MockExpiringExchanger)

	// Prepare nameservers and extra records
	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
		{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeNS}, Ns: "ns3.example.com."},
	}
	extra := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
	}
	ctx := context.TODO()

	// Mock the exchanger behavior if needed (e.g., to enrich the pool)
	mockExchanger.On("exchange", mock.Anything, mock.Anything).Return(&Response{
		Msg: &dns.Msg{
			Answer: []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.54")},
				&dns.A{Hdr: dns.RR_Header{Name: "ns3.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.55")},
			},
		},
		Duration: 10 * time.Millisecond,
	})

	// Execute
	z, err := createZone(ctx, context.Background(), "example.com.", "com.", nameservers, extra, mockExchanger, ConfigBuilder()) // default config

	// AssertionsOk
	assert.NoError(t, err)
	assert.NotNil(t, z)
	assert.Equal(t, "example.com.", z.name())

	// We'll peek under the covers to ensure the pool was created as expected.
	pool, ok := z.(*zoneImpl).pool.(*nameserverPool)
	assert.True(t, ok)

	for i := 1; i <= 10; i++ {
		// Not really nice testing across multi-threads, but this seems deterministic enough.
		time.Sleep(time.Duration(i) * 10 * time.Millisecond)
		if pool.status() == PoolPrimed {
			break
		}
	}
	assert.Equal(t, pool.status(), PoolPrimed)
}

// TestResolver_ShutdownCancelsBackgroundEnrichment verifies that background
// pool enrichment runs on the resolver lifecycle context: it survives request
// cancellation but is aborted by Shutdown.
func TestResolver_ShutdownCancelsBackgroundEnrichment(t *testing.T) {
	started := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)
	blocking := &mockExchanger{mockExchange: func(ctx context.Context, qmsg *dns.Msg) *Response {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		select {
		case cancelled <- struct{}{}:
		default:
		}
		return &Response{Err: ctx.Err()}
	}}

	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
	}
	extra := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
	}

	resolver := NewResolver(ConfigBuilder())

	z, err := resolver.funcs.createZone(context.Background(), "example.com.", ".", nameservers, extra, blocking, resolver.config)
	require.NoError(t, err)
	require.NotNil(t, z)

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("background enrichment did not start")
	}

	resolver.Shutdown()
	resolver.Shutdown() // idempotent

	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("background enrichment was not cancelled by Shutdown")
	}
}

// openFDs reports how many file descriptors the test process currently holds.
func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Logf("cannot count open FDs: %v", err)
		return -1
	}
	return len(entries)
}

// TestResolver_BackgroundEnrichmentOutlivesRequest demonstrates that background
// pool enrichment keeps holding a goroutine (and keeps doing exchanges) after
// the request that created the zone has ended; only Shutdown stops it.
func TestResolver_BackgroundEnrichmentOutlivesRequest(t *testing.T) {
	started := make(chan struct{}, 1)
	stopped := make(chan struct{}, 1)
	blocking := &mockExchanger{mockExchange: func(ctx context.Context, qmsg *dns.Msg) *Response {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		select {
		case stopped <- struct{}{}:
		default:
		}
		return &Response{Err: ctx.Err()}
	}}

	nameservers := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
	}
	extra := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
	}

	resolver := NewResolver(ConfigBuilder())

	reqCtx, reqCancel := context.WithCancel(context.Background())
	z, err := resolver.funcs.createZone(reqCtx, "example.com.", ".", nameservers, extra, blocking, resolver.config)
	require.NoError(t, err)
	require.NotNil(t, z)

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("background enrichment did not start")
	}
	t.Logf("while enrichment runs: goroutines=%d openFDs=%d", runtime.NumGoroutine(), openFDs(t))

	reqCancel() // the request that created the zone ends here

	select {
	case <-stopped:
		t.Fatal("enrichment stopped when the request ended; expected it to keep running until Shutdown")
	case <-time.After(300 * time.Millisecond):
	}
	t.Logf("after request ended:  goroutines=%d openFDs=%d", runtime.NumGoroutine(), openFDs(t))

	resolver.Shutdown()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not stop background enrichment")
	}
}
