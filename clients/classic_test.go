package clients

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/mr-torgue/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestCase struct {
	name          string
	qname         string
	qtype         string
	ns            string // ns is in IP format (no port number)
	tlsHostname   string // in case of TLS or QUIC
	rd            bool   // sets recursion
	verify        bool
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

func TestLookupClassic_UDP_TCP(t *testing.T) {

	tests := []TestCaseConfig{
		{
			name:       "UDP client with 10 second timeout and no TCP fallback",
			clientType: "udp",
			timeout:    2 * time.Second,
			testCases: []TestCase{
				{"[UDP] Client should return A record of folmer.info", "folmer.info", "A", "8.8.8.8", "dns.google", true, false, dns.RcodeSuccess, 10, "65.109.0.142", ""},
				{"[UDP] Use different resolver", "folmer.info", "A", "9.9.9.9", "dns.quad9.net", true, false, dns.RcodeSuccess, 10, "65.109.0.142", ""},
				{"[UDP] Use different RR (TXT)", "folmer.info", "TXT", "9.9.9.9", "dns.quad9.net", true, false, dns.RcodeSuccess, 10, "protonmail-verification=9fcd905c800df450c63a61d5585f0ad3439bc0f5", ""},
				{"[UDP] Set RD to false with public resolver", "folmer.info", "TXT", "8.8.8.8", "dns.google", false, false, dns.RcodeServerFailure, 10, "", ""}, // don't know why ServFail
				{"[UDP] Set RD to false with root server", "folmer.info", "TXT", "198.41.0.4", "a.root-servers.net", false, false, dns.RcodeSuccess, 10, "a0.info.afilias-nst.info.", ""},
				// use different domain
				{"[UDP] Client should return NXDomain", "a.com", "A", "8.8.8.8", "dns.google", true, false, dns.RcodeNameError, 10, "", ""},
				{"[UDP] Client should not use TCP fallback", "cisco.com", "TXT", "8.8.8.8", "dns.google", true, false, dns.RcodeSuccess, 10, "", "truncated"},
				{"[UDP] Client should timeout", "folmer.info", "A", "8.8.8.8", "dns.google", true, false, dns.RcodeSuccess, 0, "65.109.0.142", "dial udp 8.8.8.8:53: i/o timeout"},
			},
		},
		{
			name:       "UDP client with 0 second timeout",
			clientType: "udp",
			timeout:    1, // 0 is ignored
			testCases: []TestCase{
				{"[UDP] Client should timeout (global)", "folmer.info", "A", "8.8.8.8", "dns.google", true, false, dns.RcodeSuccess, 1, "65.109.0.142", "dial udp 8.8.8.8:53: i/o timeout"},
			},
		},
		{
			name:       "TCP client with 10 second timeout",
			clientType: "tcp",
			timeout:    10 * time.Second,
			testCases: []TestCase{
				{"[TCP] Client should return A record of folmer.info", "folmer.info", "A", "8.8.8.8", "dns.google", true, false, dns.RcodeSuccess, 2, "65.109.0.142", ""},
			},
		},
	}

	// loop over client configurations
	for _, ttconfig := range tests {
		client := ClassicClient{
			Port:   "53",
			Client: &dns.Client{Net: ttconfig.clientType, Timeout: ttconfig.timeout},
		}
		for _, tt := range ttconfig.testCases {
			t.Run(tt.name, func(t *testing.T) {
				qmsg := new(dns.Msg)
				qmsg.SetQuestion(dns.Fqdn(tt.qname), dns.StringToType[tt.qtype])
				qmsg.MsgHdr.RecursionDesired = tt.rd

				ctx, _ := context.WithTimeout(context.Background(), tt.timeout*time.Second)
				rmsg, rtt, err := client.ExchangeContext(ctx, qmsg, tt.ns)

				if tt.expectedError == "truncated" {
					assert.True(t, rmsg.Truncated, "truncated flag should be set")
				} else if tt.expectedError != "" {
					assert.NotNil(t, err, "expected an error")
					assert.ErrorContains(t, err, tt.expectedError, "lookup errors should match")
				} else {
					assert.Nil(t, err, "err should be nil")
					assert.Greater(t, ttconfig.timeout, rtt, "timeout > rtt")
					require.NotNil(t, rmsg, "rmsg should not be nil")
					assert.Equal(t, tt.rcode, rmsg.Rcode, "rcodes should match")
					assert.Contains(t, rmsg.String(), tt.expected, "answers should match")
				}
			})
		}
	}
}

func TestLookupClassic_TLS(t *testing.T) {

	tests := []TestCaseConfig{
		{
			name:       "TCP client with 10 second timeout",
			clientType: "tcp-tls",
			timeout:    10 * time.Second,
			testCases: []TestCase{
				{"[TLS] Client should return A record of folmer.info", "folmer.info", "A", "8.8.8.8", "dns.google", true, false, dns.RcodeSuccess, 2, "65.109.0.142", ""},
				{"[TLS] Test with verify", "folmer.info", "A", "8.8.8.8", "dns.google", true, true, dns.RcodeSuccess, 2, "65.109.0.142", ""},
				{"[TLS] Test with verify with wrong hostname", "folmer.info", "A", "8.8.8.8", "dns.gogle", true, true, dns.RcodeSuccess, 2, "65.109.0.142", "failed to verify certificate"},
				{"[TLS] Nameserver does not understand TLS", "folmer.info", "A", "192.48.79.30", "j.gtld-servers.net.", true, false, dns.RcodeSuccess, 2, "65.109.0.142", "context deadline exceeded"},
			},
		},
	}

	// loop over client configurations
	for _, ttconfig := range tests {
		for _, tt := range ttconfig.testCases {
			t.Run(tt.name, func(t *testing.T) {

				client := ClassicClient{
					Port: "853",
					Client: &dns.Client{
						Net:     ttconfig.clientType,
						Timeout: ttconfig.timeout,
						TLSConfig: &tls.Config{
							ServerName:         dns.Fqdn(tt.tlsHostname),
							InsecureSkipVerify: !tt.verify,
						},
					},
				}

				qmsg := new(dns.Msg)
				qmsg.SetQuestion(dns.Fqdn(tt.qname), dns.StringToType[tt.qtype])
				qmsg.MsgHdr.RecursionDesired = tt.rd

				ctx, _ := context.WithTimeout(context.Background(), tt.timeout*time.Second)
				rmsg, rtt, err := client.ExchangeContext(ctx, qmsg, tt.ns)

				if tt.expectedError == "truncated" {
					assert.True(t, rmsg.Truncated, "truncated flag should be set")
				} else if tt.expectedError != "" {
					assert.NotNil(t, err, "expected an error")
					assert.ErrorContains(t, err, tt.expectedError, "lookup errors should match")
				} else {
					assert.Nil(t, err, "err should be nil")
					assert.Greater(t, ttconfig.timeout, rtt, "timeout > rtt")
					require.NotNil(t, rmsg, "rmsg should not be nil")
					assert.Equal(t, tt.rcode, rmsg.Rcode, "rcodes should match")
					assert.Contains(t, rmsg.String(), tt.expected, "answers should match")
				}
			})
		}
	}
}
