package clients

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupDoQ(t *testing.T) {

	type TestCase struct {
		name          string
		qname         string
		qtype         string
		ns            string // ns is in IP format (no port number)
		tlsHostname   string // in case of TLS or QUIC
		rd            bool   // sets recursion
		rcode         int
		timeout       time.Duration
		expected      string // uses string.contains, which is not optimal
		expectedError string
	}

	type TestCaseConfig struct {
		name       string
		clientType string
		timeout    time.Duration
		testCases  []TestCase
	}

	tests := []TestCaseConfig{
		{
			name:       "DoQ client with timeout",
			clientType: "doq",
			timeout:    2 * time.Second,
			testCases: []TestCase{
				{"[QUIC] Client should timeout", "miek.nl", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 4, "45.138.52.215", "context deadline exceeded"},
				{"[QUIC] Client should timeout with smaller timeout", "miek.nl", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 1, "45.138.52.215", "context deadline exceeded"},
				{"[QUIC] Client should give result", "miek.nl", "A", "9.9.9.9", "dns.quad9.net", true, dns.RcodeSuccess, 1, "45.138.52.215", ""},
				//{"[QUIC] Client should give result", "miek.nl", "A", "9.9.9.9", "dns.quad9.net", true, dns.RcodeSuccess, 1, "45.138.52.215", ""},
			},
		},
	}

	// loop over client configurations
	for _, ttconfig := range tests {
		for _, tt := range ttconfig.testCases {
			t.Run(tt.name, func(t *testing.T) {

				tlsconf := &tls.Config{
					NextProtos:         []string{"doq"},
					ServerName:         dns.Fqdn(tt.tlsHostname),
					InsecureSkipVerify: false,
				}
				client := DOQClient{
					Port:      "853",
					TLSConfig: tlsconf,
					Timeout:   ttconfig.timeout,
				}

				qmsg := new(dns.Msg)
				qmsg.SetQuestion(dns.Fqdn(tt.qname), dns.StringToType[tt.qtype])
				qmsg.MsgHdr.RecursionDesired = tt.rd

				ctx, _ := context.WithTimeout(context.Background(), tt.timeout*time.Second)
				rmsg, rtt, err := client.ExchangeContext(ctx, qmsg, tt.ns)

				if tt.expectedError != "" {
					assert.NotNil(t, err, "expected an error")
					assert.ErrorContains(t, err, tt.expectedError, "lookup errors should match")
				} else {
					assert.Greater(t, ttconfig.timeout, rtt, "timeout > rtt")
					require.NotNil(t, rmsg, "rmsg should not be nil")
					assert.Equal(t, tt.rcode, rmsg.Rcode, "rcodes should match")
					assert.Contains(t, rmsg.String(), tt.expected, "answers should match")
				}
			})
		}
	}
}

func TestLookupDoQ_TC(t *testing.T) {
	// should not set the TC flag
	qname := dns.Fqdn("miek.nl.")
	tlsconf := &tls.Config{
		NextProtos:         []string{"doq"},
		ServerName:         dns.Fqdn("dns.quad9.net"),
		InsecureSkipVerify: false,
	}
	client := DOQClient{
		Port:      "853",
		TLSConfig: tlsconf,
		Timeout:   10 * time.Second,
	}

	qmsg := new(dns.Msg)
	qmsg.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	qmsg.MsgHdr.RecursionDesired = true

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	rmsg, _, err := client.ExchangeContext(ctx, qmsg, "9.9.9.9")
	assert.Nil(t, err)
	assert.NotNil(t, rmsg)
	assert.False(t, rmsg.Truncated)
}

func TestLookupDoQ_DNSTestDev(t *testing.T) {
	type DNSTestCase struct {
		name       string
		qname      string
		rcode      int
		checkRcode bool
		ad         bool
		checkAD    bool
		expected   string
	}

	tests := []DNSTestCase{
		{"alg13.dnstest.dev apex (ECDSA P-256) returns AD answer", "alg13.dnstest.dev", dns.RcodeSuccess, true, true, true, "188.114.96.0"},
		{"valid.alg13.dnstest.dev returns AD answer", "valid.alg13.dnstest.dev", dns.RcodeSuccess, true, true, true, "188.114.96.0"},
		{"invalid.alg13.dnstest.dev is rejected", "invalid.alg13.dnstest.dev", dns.RcodeServerFailure, true, false, true, ""},
		{"expired.alg13.dnstest.dev is rejected", "expired.alg13.dnstest.dev", dns.RcodeServerFailure, true, false, true, ""},
		{"invalid-dnskey.alg13.dnstest.dev", "invalid-dnskey.alg13.dnstest.dev", 0, false, false, false, ""},
		{"expired-dnskey.alg13.dnstest.dev", "expired-dnskey.alg13.dnstest.dev", 0, false, false, false, ""},
		{"mldsa44.dnstest.dev apex (ML-DSA-44)", "mldsa44.dnstest.dev", dns.RcodeSuccess, false, false, false, ""},
		{"valid.mldsa44.dnstest.dev", "valid.mldsa44.dnstest.dev", dns.RcodeSuccess, false, false, false, ""},
		{"invalid.mldsa44.dnstest.dev", "invalid.mldsa44.dnstest.dev", dns.RcodeSuccess, false, false, false, ""},
		{"expired.mldsa44.dnstest.dev", "expired.mldsa44.dnstest.dev", dns.RcodeSuccess, false, false, false, ""},
		{"invalid-dnskey.mldsa44.dnstest.dev", "invalid-dnskey.mldsa44.dnstest.dev", dns.RcodeSuccess, false, false, false, ""},
		{"expired-dnskey.mldsa44.dnstest.dev", "expired-dnskey.mldsa44.dnstest.dev", dns.RcodeSuccess, false, false, false, ""},
		{"dual-valid.mldsa44.dnstest.dev", "dual-valid.mldsa44.dnstest.dev", dns.RcodeSuccess, false, false, false, ""},
		{"upgrade.mldsa44.dnstest.dev", "upgrade.mldsa44.dnstest.dev", dns.RcodeSuccess, false, false, false, ""},
		{"downgrade.mldsa44.dnstest.dev", "downgrade.mldsa44.dnstest.dev", dns.RcodeSuccess, false, false, false, ""},
	}

	tlsconf := &tls.Config{
		NextProtos:         []string{"doq"},
		ServerName:         dns.Fqdn("dns.quad9.net"),
		InsecureSkipVerify: false,
	}
	client := DOQClient{
		Port:      "853",
		TLSConfig: tlsconf,
		Timeout:   5 * time.Second,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qmsg := new(dns.Msg)
			qmsg.SetQuestion(dns.Fqdn(tt.qname), dns.TypeA)
			qmsg.SetEdns0(1232, true)
			qmsg.MsgHdr.RecursionDesired = true

			ctx, _ := context.WithTimeout(context.Background(), 6*time.Second)
			rmsg, rtt, err := client.ExchangeContext(ctx, qmsg, "9.9.9.9")

			require.NoError(t, err)
			require.NotNil(t, rmsg, "rmsg should not be nil")
			assert.Greater(t, 6*time.Second, rtt, "timeout > rtt")
			if tt.checkRcode {
				assert.Equal(t, tt.rcode, rmsg.Rcode, "rcodes should match")
			}
			if tt.checkAD {
				assert.Equal(t, tt.ad, rmsg.AuthenticatedData, "AD bits should match")
			}
			if tt.expected != "" {
				assert.Contains(t, rmsg.String(), tt.expected, "answers should match")
			}
		})
	}
}
