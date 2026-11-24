package cache

import (
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cacheMsg(m *dns.Msg, tc test.Case) *dns.Msg {
	m.RecursionAvailable = tc.RecursionAvailable
	m.AuthenticatedData = tc.AuthenticatedData
	m.CheckingDisabled = tc.CheckingDisabled
	m.Authoritative = tc.Authoritative
	m.Rcode = tc.Rcode
	m.Truncated = tc.Truncated
	m.Answer = tc.Answer
	m.Ns = tc.Ns
	m.Extra = tc.Extra //don't copy Extra, because we don't care and fake EDNS0 DO with tc.Do.
	return m
}

// TestNewCache tests the creation of new caches
func TestNewCache(t *testing.T) {
	tests := []struct { // Define a struct for each test case and create a slice of them
		name     string
		capacity int
	}{
		{"Test Normal", 123},
		{"Test Default Values", 0},
		{"Test Large Values", 123456},
	}

	// test default
	c := NewCache()
	assert.NotNil(t, c.cache)
	assert.Equal(t, DefaultCapacity, c.capacity)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache(WithCapacity(tt.capacity))
			assert.NotNil(t, c.cache)
			assert.Equal(t, tt.capacity, c.capacity)
		})
	}
}

// TestCacheInsertion verifies the insertion of items to the cache.
func TestCacheInsertion(t *testing.T) {
	cacheTestCases := []struct {
		name        string
		out         test.Case // the expected message coming "out" of cache
		in          test.Case // the test message going "in" to cache
		shouldCache bool
	}{
		{
			name: "test ad bit cache",
			out: test.Case{
				Qname: "miek.nl.", Qtype: dns.TypeMX,
				Answer: []dns.RR{
					test.MX("miek.nl.	3601	IN	MX	1 aspmx.l.google.com."),
					test.MX("miek.nl.	3601	IN	MX	10 aspmx2.googlemail.com."),
				},
				RecursionAvailable: true,
				AuthenticatedData:  true,
			},
			in: test.Case{
				Qname: "miek.nl.", Qtype: dns.TypeMX,
				Answer: []dns.RR{
					test.MX("miek.nl.	3601	IN	MX	1 aspmx.l.google.com."),
					test.MX("miek.nl.	3601	IN	MX	10 aspmx2.googlemail.com."),
				},
				RecursionAvailable: true,
				AuthenticatedData:  true,
			},
			shouldCache: true,
		},
		{
			name: "test case sensitivity cache",
			out: test.Case{
				Qname: "miek.nl.", Qtype: dns.TypeMX,
				Answer: []dns.RR{
					test.MX("miek.nl.	3601	IN	MX	1 aspmx.l.google.com."),
					test.MX("miek.nl.	3601	IN	MX	10 aspmx2.googlemail.com."),
				},
				RecursionAvailable: true,
				AuthenticatedData:  true,
			},
			in: test.Case{
				Qname: "mIEK.nL.", Qtype: dns.TypeMX,
				Answer: []dns.RR{
					test.MX("miek.nl.	3601	IN	MX	1 aspmx.l.google.com."),
					test.MX("miek.nl.	3601	IN	MX	10 aspmx2.googlemail.com."),
				},
				RecursionAvailable: true,
				AuthenticatedData:  true,
			},
			shouldCache: true,
		},
		{
			name: "test truncated responses shouldn't cache",
			in: test.Case{
				Qname: "miek.nl.", Qtype: dns.TypeMX,
				Answer:    []dns.RR{test.MX("miek.nl.	1800	IN	MX	1 aspmx.l.google.com.")},
				Truncated: true,
			},
			shouldCache: false,
		},
		/* NO NEGATIVE CACHE YET
		{
			name: "test dns.RcodeNameError cache",
			out: test.Case{
				Rcode: dns.RcodeNameError,
				Qname: "example.org.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("example.org. 3600 IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2016082540 7200 3600 1209600 3600"),
				},
				RecursionAvailable: true,
			},
			in: test.Case{
				Rcode: dns.RcodeNameError,
				Qname: "example.org.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("example.org. 3600 IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2016082540 7200 3600 1209600 3600"),
				},
				RecursionAvailable: true,
			},
			shouldCache: true,
		},
		{
			name: "test dns.RcodeServerFailure cache",
			out: test.Case{
				Rcode: dns.RcodeServerFailure,
				Qname: "example.org.", Qtype: dns.TypeA,
				Ns:                 []dns.RR{},
				RecursionAvailable: true,
			},
			in: test.Case{
				Rcode: dns.RcodeServerFailure,
				Qname: "example.org.", Qtype: dns.TypeA,
				Ns:                 []dns.RR{},
				RecursionAvailable: true,
			},
			shouldCache: true,
		},
		{
			name: "test dns.RcodeNotImplemented cache",
			out: test.Case{
				Rcode: dns.RcodeNotImplemented,
				Qname: "example.org.", Qtype: dns.TypeA,
				Ns:                 []dns.RR{},
				RecursionAvailable: true,
			},
			in: test.Case{
				Rcode: dns.RcodeNotImplemented,
				Qname: "example.org.", Qtype: dns.TypeA,
				Ns:                 []dns.RR{},
				RecursionAvailable: true,
			},
			shouldCache: true,
		},*/
		{
			name: "test expired RRSIG doesn't cache",
			in: test.Case{
				Qname: "miek.nl.", Qtype: dns.TypeMX,
				Do: true,
				Answer: []dns.RR{
					test.MX("miek.nl.	3600	IN	MX	1 aspmx.l.google.com."),
					test.MX("miek.nl.	3600	IN	MX	10 aspmx2.googlemail.com."),
					test.RRSIG("miek.nl.	1800	IN	RRSIG	MX 8 2 1800 20160521031301 20160421031301 12051 miek.nl. lAaEzB5teQLLKyDenatmyhca7blLRg9DoGNrhe3NReBZN5C5/pMQk8Jc u25hv2fW23/SLm5IC2zaDpp2Fzgm6Jf7e90/yLcwQPuE7JjS55WMF+HE LEh7Z6AEb+Iq4BWmNhUz6gPxD4d9eRMs7EAzk13o1NYi5/JhfL6IlaYy qkc="),
				},
				RecursionAvailable: true,
			},
			shouldCache: false,
		},
		{
			name: "test DO bit with RRSIG not expired cache",
			out: test.Case{
				Qname: "example.org.", Qtype: dns.TypeMX,
				Do: true,
				Answer: []dns.RR{
					test.MX("example.org.	3600	IN	MX	1 aspmx.l.google.com."),
					test.MX("example.org.	3600	IN	MX	10 aspmx2.googlemail.com."),
					test.RRSIG("example.org.	1800	IN	RRSIG	MX 8 2 1800 20170521031301 20170421031301 12051 miek.nl. lAaEzB5teQLLKyDenatmyhca7blLRg9DoGNrhe3NReBZN5C5/pMQk8Jc u25hv2fW23/SLm5IC2zaDpp2Fzgm6Jf7e90/yLcwQPuE7JjS55WMF+HE LEh7Z6AEb+Iq4BWmNhUz6gPxD4d9eRMs7EAzk13o1NYi5/JhfL6IlaYy qkc="),
				},
				RecursionAvailable: true,
			},
			in: test.Case{
				Qname: "example.org.", Qtype: dns.TypeMX,
				Do: true,
				Answer: []dns.RR{
					test.MX("example.org.	3600	IN	MX	1 aspmx.l.google.com."),
					test.MX("example.org.	3600	IN	MX	10 aspmx2.googlemail.com."),
					test.RRSIG("example.org.	1800	IN	RRSIG	MX 8 2 1800 20170521031301 20170421031301 12051 miek.nl. lAaEzB5teQLLKyDenatmyhca7blLRg9DoGNrhe3NReBZN5C5/pMQk8Jc u25hv2fW23/SLm5IC2zaDpp2Fzgm6Jf7e90/yLcwQPuE7JjS55WMF+HE LEh7Z6AEb+Iq4BWmNhUz6gPxD4d9eRMs7EAzk13o1NYi5/JhfL6IlaYy qkc="),
				},
				RecursionAvailable: true,
			},
			shouldCache: true,
		},
		{
			name: "test CD bit cache",
			out: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: "dnssec-failed.org.",
				Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("dnssec-failed.org. 3600 IN	A	127.0.0.1"),
				},
				CheckingDisabled: true,
			},
			in: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: "dnssec-failed.org.",
				Answer: []dns.RR{
					test.A("dnssec-failed.org. 3600 IN	A	127.0.0.1"),
				},
				Qtype:            dns.TypeA,
				CheckingDisabled: true,
			},
			shouldCache: true,
		},
		/* WE DON'T HAVE EXCEPTIONS LISTS YET
		{
			name: "test negative zone exception shouldn't cache",
			in: test.Case{
				Rcode: dns.RcodeNameError,
				Qname: "neg-disabled.example.org.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("example.org. 3600 IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2016082540 7200 3600 1209600 3600"),
				},
			},
			shouldCache: false,
		},
		{
			name: "test positive zone exception shouldn't cache",
			in: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: "pos-disabled.example.org.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("pos-disabled.example.org. 3600 IN	A	127.0.0.1"),
				},
			},
			shouldCache: false,
		},
		{
			name: "test positive zone exception with negative answer cache",
			in: test.Case{
				Rcode: dns.RcodeNameError,
				Qname: "pos-disabled.example.org.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("example.org. 3600 IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2016082540 7200 3600 1209600 3600"),
				},
			},
			out: test.Case{
				Rcode: dns.RcodeNameError,
				Qname: "pos-disabled.example.org.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("example.org. 3600 IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2016082540 7200 3600 1209600 3600"),
				},
			},
			shouldCache: true,
		},*/
		{
			name: "test negative zone exception with positive answer cache",
			in: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: "neg-disabled.example.org.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("neg-disabled.example.org. 3600 IN	A	127.0.0.1"),
				},
			},
			out: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: "neg-disabled.example.org.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("neg-disabled.example.org. 3600 IN	A	127.0.0.1"),
				},
			},
			shouldCache: true,
		},
		{
			name: "test root zone",
			in: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: ".", Qtype: dns.TypeNS,
				Answer: []dns.RR{
					test.NS(". 3600000 NS A.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS B.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS C.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS D.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS E.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS F.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS G.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS H.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS I.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS J.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS k.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS L.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS M.ROOT-SERVERS.NET."),
				},
			},
			out: test.Case{
				Rcode: dns.RcodeSuccess,
				Qname: ".", Qtype: dns.TypeNS,
				Answer: []dns.RR{
					test.NS(". 3600000 NS A.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS B.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS C.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS D.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS E.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS F.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS G.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS H.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS I.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS J.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS k.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS L.ROOT-SERVERS.NET."),
					test.NS(". 3600000 NS M.ROOT-SERVERS.NET."),
				},
			},
			shouldCache: true,
		},
	}

	now, _ := time.Parse(time.UnixDate, "Fri Apr 21 10:51:21 BST 2017")

	for _, tc := range cacheTestCases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache()

			m := tc.in.Msg()
			m = cacheMsg(m, tc.in)
			c.UpdateWithTime(m.Question[0], m, Indeterminate, now)
			if tc.in.Do {
				// A DO query is only served validated entries, so simulate the
				// post-validation update that the resolver performs.
				c.UpdateWithTime(m.Question[0], m, Secure, now)
			}
			resp, err := c.GetWithTime(m, now)
			//require.Nil(t, err)
			found := err == nil

			if !tc.shouldCache && found {
				t.Fatalf("Cached message that should not have been cached: %s", resp.Question[0].Name)
			}
			if tc.shouldCache && !found {
				t.Fatalf("Did not cache message that should have been cached: %s. %+v, %s", tc.name, resp, err)
			}

			if found {

				// TODO: If we incorporate these individual checks into the
				//       test.Header function, we can eliminate them from here.
				// Cache entries are always Authoritative.
				assert.True(t, resp.Authoritative)
				// We don't test this yet: DNSSEC is not enabled for cache
				//assert.Equal(t, tc.out.AuthenticatedData, resp.AuthenticatedData)
				//assert.Equal(t, tc.out.RecursionAvailable, resp.RecursionAvailable)
				//assert.Equal(t, tc.out.CheckingDisabled, resp.CheckingDisabled)
				assert.True(t, resp.Response)

				if err := test.Header(tc.out, resp); err != nil {
					t.Logf("Cache %v", resp)
					t.Error(err)
				}
				if err := test.Section(tc.out, test.Answer, resp.Answer); err != nil {
					t.Logf("Cache %v -- %v", test.Answer, resp.Answer)
					t.Error(err)
				}
				if err := test.Section(tc.out, test.Ns, resp.Ns); err != nil {
					t.Error(err)
				}
				if err := test.Section(tc.out, test.Extra, resp.Extra); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func testNow() time.Time {
	now, _ := time.Parse(time.UnixDate, "Fri Apr 21 10:51:21 BST 2017")
	return now
}

func queryMsg(qname string, qtype uint16, do bool) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(qname), qtype)
	if do {
		q.SetEdns0(1232, true)
	}
	return q
}

// TestCacheValidationGate tests that validation status is recorded on entries
// and enforced on Get: unvalidated entries are not served to DO queries,
// Secure entries are served with AD, and Bogus entries are never served.
func TestCacheValidationGate(t *testing.T) {
	now := testNow()
	c := NewCache()

	in := test.Case{
		Qname: "secure.example.", Qtype: dns.TypeA,
		Answer: []dns.RR{test.A("secure.example. 3600 IN A 127.0.0.1")},
	}
	m := cacheMsg(in.Msg(), in)
	qDO := queryMsg("secure.example.", dns.TypeA, true)
	qNoDO := queryMsg("secure.example.", dns.TypeA, false)

	require.NoError(t, c.UpdateWithTime(m.Question[0], m, Indeterminate, now))

	// DO query must not be served an unvalidated entry.
	_, err := c.GetWithTime(qDO, now)
	assert.ErrorIs(t, err, ErrNotValidated)

	// Non-DO query is served, but without AD.
	resp, err := c.GetWithTime(qNoDO, now)
	require.NoError(t, err)
	assert.False(t, resp.AuthenticatedData)
	assert.Equal(t, 1, len(resp.Answer))
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

	// CD bit disables the gate.
	qCD := queryMsg("secure.example.", dns.TypeA, true)
	qCD.CheckingDisabled = true
	resp, err = c.GetWithTime(qCD, now)
	require.NoError(t, err)
	assert.False(t, resp.AuthenticatedData)

	// After validation, the entry is served to DO queries with AD set.
	require.NoError(t, c.UpdateWithTime(m.Question[0], m, Secure, now))
	resp, err = c.GetWithTime(qDO, now)
	require.NoError(t, err)
	assert.True(t, resp.AuthenticatedData)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	assert.Equal(t, 1, len(resp.Answer))

	// Insecure is served, but without AD.
	require.NoError(t, c.UpdateWithTime(m.Question[0], m, Insecure, now))
	resp, err = c.GetWithTime(qDO, now)
	require.NoError(t, err)
	assert.False(t, resp.AuthenticatedData)

	// Bogus entries are removed and never served.
	require.NoError(t, c.UpdateWithTime(m.Question[0], m, Bogus, now))
	_, err = c.GetWithTime(qDO, now)
	assert.ErrorIs(t, err, ErrCacheMiss)
	_, err = c.GetWithTime(qNoDO, now)
	assert.ErrorIs(t, err, ErrCacheMiss)

	// Safety net: even a manually inserted Bogus entry is not served.
	k := Key("secure.example.", dns.TypeA)
	c.cache.Add(k, &Entry{Name: "secure.example.", Type: dns.TypeA, Status: Bogus, Rcode: dns.RcodeSuccess, Records: []dns.RR{test.A("secure.example. 3600 IN A 127.0.0.1")}, TTL: 3600, Expires: now.Add(time.Hour)})
	_, err = c.GetWithTime(qNoDO, now)
	assert.ErrorIs(t, err, ErrCacheMiss)
}

// TestCacheNoDowngradeOfValidatedEntry tests that a later unvalidated insert
// does not overwrite an already validated entry.
func TestCacheNoDowngradeOfValidatedEntry(t *testing.T) {
	now := testNow()
	c := NewCache()

	in := test.Case{
		Qname: "node.example.", Qtype: dns.TypeA,
		Answer: []dns.RR{test.A("node.example. 3600 IN A 127.0.0.1")},
	}
	m := cacheMsg(in.Msg(), in)
	qDO := queryMsg("node.example.", dns.TypeA, true)

	require.NoError(t, c.UpdateWithTime(m.Question[0], m, Indeterminate, now))
	require.NoError(t, c.UpdateWithTime(m.Question[0], m, Secure, now))
	// A second, unvalidated update arrives (e.g. concurrent query).
	require.NoError(t, c.UpdateWithTime(m.Question[0], m, Indeterminate, now))

	resp, err := c.GetWithTime(qDO, now)
	require.NoError(t, err)
	assert.True(t, resp.AuthenticatedData)
}

// TestCacheKeyIdentityCheck tests that a hash collision does not serve the
// wrong entry: Get verifies the entry's name and type against the question.
func TestCacheKeyIdentityCheck(t *testing.T) {
	now := testNow()
	c := NewCache()

	q := queryMsg("victim.example.", dns.TypeA, false)
	k := Key("victim.example.", dns.TypeA)
	// Simulate a collision: an entry stored under the same key, but for another name.
	c.cache.Add(k, &Entry{Name: "other.example.", Type: dns.TypeA, Status: Secure, Rcode: dns.RcodeSuccess, Records: []dns.RR{test.A("other.example. 3600 IN A 127.0.0.2")}, TTL: 3600, Expires: now.Add(time.Hour)})

	_, err := c.GetWithTime(q, now)
	assert.ErrorIs(t, err, ErrCacheMiss)

	// Case-insensitive match of the same name must hit.
	q2 := queryMsg("ViCtIm.ExAmPlE.", dns.TypeA, false)
	c.cache.Add(k, &Entry{Name: "victim.example.", Type: dns.TypeA, Status: Insecure, Rcode: dns.RcodeSuccess, Records: []dns.RR{test.A("victim.example. 3600 IN A 127.0.0.1")}, TTL: 3600, Expires: now.Add(time.Hour)})
	resp, err := c.GetWithTime(q2, now)
	require.NoError(t, err)
	assert.Equal(t, 1, len(resp.Answer))
}

// TestCacheTTLDecrementAndExpiry tests that TTLs are decremented by the time
// spent in cache and that entries expire.
func TestCacheTTLDecrementAndExpiry(t *testing.T) {
	now := testNow()
	c := NewCache()

	in := test.Case{
		Qname: "ttl.example.", Qtype: dns.TypeA,
		Answer: []dns.RR{test.A("ttl.example. 3600 IN A 127.0.0.1")},
	}
	m := cacheMsg(in.Msg(), in)
	require.NoError(t, c.UpdateWithTime(m.Question[0], m, Indeterminate, now))

	q := queryMsg("ttl.example.", dns.TypeA, false)

	resp, err := c.GetWithTime(q, now.Add(100*time.Second))
	require.NoError(t, err)
	assert.Equal(t, uint32(3500), resp.Answer[0].Header().Ttl)

	_, err = c.GetWithTime(q, now.Add(3601*time.Second))
	assert.ErrorIs(t, err, ErrCacheExpired)
}

// TestCacheCopiesRecords tests that entries deep-copy records on insert and
// copy on read, so neither the caller's message nor a served message can
// mutate the cache.
func TestCacheCopiesRecords(t *testing.T) {
	now := testNow()
	c := NewCache()

	m := new(dns.Msg)
	m.SetQuestion("copy.example.", dns.TypeA)
	m.Answer = make([]dns.RR, 1, 4) // extra capacity: old code's append clobbered this
	m.Answer[0] = test.A("copy.example. 3600 IN A 127.0.0.1")
	m.Ns = []dns.RR{test.NS("copy.example. 3600 IN NS ns1.copy.example.")}

	require.NoError(t, c.UpdateWithTime(m.Question[0], m, Indeterminate, now))

	// Mutating the source message after insert must not affect the cache.
	m.Answer[0].Header().Ttl = 1
	assert.Equal(t, 1, len(m.Answer), "answer section of the source message must not be clobbered")

	q := queryMsg("copy.example.", dns.TypeA, false)
	resp, err := c.GetWithTime(q, now)
	require.NoError(t, err)
	require.Equal(t, 1, len(resp.Answer))
	assert.Equal(t, uint32(3600), resp.Answer[0].Header().Ttl)

	// Mutating a served message must not affect the cache either.
	resp.Answer[0].Header().Ttl = 5
	resp2, err := c.GetWithTime(q, now)
	require.NoError(t, err)
	assert.Equal(t, uint32(3600), resp2.Answer[0].Header().Ttl)
}

// TestCacheNegativeResponse tests that negative responses (NXDOMAIN / NODATA)
// are cached under the question key with their rcode and authority records.
func TestCacheNegativeResponse(t *testing.T) {
	now := testNow()

	tests := []struct {
		name     string
		rcode    int
		qname    string
	}{
		{"NXDOMAIN", dns.RcodeNameError, "nx.example."},
		{"NODATA", dns.RcodeSuccess, "nodata.example."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache()
			in := test.Case{
				Rcode: tt.rcode,
				Qname: tt.qname, Qtype: dns.TypeA,
				Ns: []dns.RR{test.SOA("example. 3600 IN SOA ns1.example. hostmaster.example. 1 7200 3600 1209600 300")},
			}
			m := cacheMsg(in.Msg(), in)
			require.NoError(t, c.UpdateWithTime(m.Question[0], m, Indeterminate, now))

			q := queryMsg(tt.qname, dns.TypeA, false)
			resp, err := c.GetWithTime(q, now)
			require.NoError(t, err)
			assert.Equal(t, tt.rcode, resp.Rcode)
			assert.Equal(t, 0, len(resp.Answer))
			require.Equal(t, 1, len(resp.Ns))
			assert.Equal(t, dns.TypeSOA, resp.Ns[0].Header().Rrtype)
			assert.Equal(t, uint32(3600), resp.Ns[0].Header().Ttl)
		})
	}
}

// TestCacheRcodeRecorded tests that the entry rcode is populated on insert.
func TestCacheRcodeRecorded(t *testing.T) {
	now := testNow()
	c := NewCache()

	in := test.Case{
		Rcode: dns.RcodeNameError,
		Qname: "rc.example.", Qtype: dns.TypeA,
		Ns:    []dns.RR{test.SOA("example. 3600 IN SOA ns1.example. hostmaster.example. 1 7200 3600 1209600 300")},
	}
	m := cacheMsg(in.Msg(), in)
	require.NoError(t, c.UpdateWithTime(m.Question[0], m, Indeterminate, now))

	k := Key("rc.example.", dns.TypeA)
	val, ok := c.cache.Get(k)
	require.True(t, ok)
	require.NotNil(t, val)
	assert.Equal(t, dns.RcodeNameError, val.Rcode)
	assert.Equal(t, Indeterminate, val.Status)
}
