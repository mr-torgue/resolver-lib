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
				{"[QUIC] Client should timeout", "folmer.info", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 4, "65.109.0.142", "context deadline exceeded"},
				{"[QUIC] Client should timeout with smaller timeout", "folmer.info", "A", "8.8.8.8", "dns.google", true, dns.RcodeSuccess, 1, "65.109.0.142", "context deadline exceeded"},
				{"[QUIC] Client should give result", "folmer.info", "A", "9.9.9.9", "dns.quad9.net", true, dns.RcodeSuccess, 1, "65.109.0.142", ""},
				{"[QUIC] Client should give result", "folmer.info", "A", "9.9.9.9", "dns.quad9.net", true, dns.RcodeSuccess, 1, "65.109.0.142", ""},
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
