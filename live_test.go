//go:build live

package resolver

import (
	"context"
	"fmt"
	"testing"

	"github.com/mr-torgue/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Live tests perform real DNS queries against the public Internet.
// They are excluded from the default test run; enable with: go test -tags live

func Test_exchange(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		hostname           string
		addr               string
		client             string
		expectedClient     string
		insecureSkipVerify bool
		expectPanic        bool
		testCases          []TestCase
	}{
		{
			name:               "Github nameserver with UDP",
			hostname:           "dns1.p08.nsone.net.",
			addr:               "198.51.44.8",
			client:             "udp",
			expectedClient:     "*clients.ClassicClient",
			insecureSkipVerify: false,
			testCases: []TestCase{
				{
					name:              "[UDP] Client should return A record and CNAME record of www.github.com ",
					qname:             "www.github.com",
					qtype:             dns.TypeA,
					rcode:             dns.RcodeSuccess,
					expectedNrAnswers: 2,
					expectedAnswers: []ExpectedRR{
						{dns.TypeA, "4.237.22.38"},
						{dns.TypeCNAME, "github.com."},
					},
					expectedNrAuth: 0,
					expectedAuth:   []ExpectedRR{},
				},
			},
		},
		{
			name:               "Github nameserver with QUIC",
			hostname:           "dns.quad9.net.",
			addr:               "9.9.9.9",
			client:             "doq",
			expectedClient:     "*clients.DOQClient",
			insecureSkipVerify: false,
			testCases: []TestCase{
				{
					name:              "[DOQ] Client should return A record and CNAME record of www.github.com ",
					qname:             "www.github.com",
					qtype:             dns.TypeA,
					rcode:             dns.RcodeSuccess,
					rd:                true,
					expectedNrAnswers: 2,
					expectedAnswers: []ExpectedRR{
						{dns.TypeA, "4.237.22.38"},
						{dns.TypeCNAME, "github.com."},
					},
					expectedNrAuth: 0,
					expectedAuth:   []ExpectedRR{},
				},
			},
		},
		{
			name:               "Github nameserver with QUIC (should not work)",
			hostname:           "dns1.p08.nsone.net.",
			addr:               "198.51.44.8",
			client:             "doq",
			expectedClient:     "*clients.DOQClient",
			insecureSkipVerify: false,
			testCases: []TestCase{
				{
					name:          "[DOQ] Client should return A record and CNAME record of www.github.com ",
					qname:         "www.github.com",
					qtype:         dns.TypeA,
					rcode:         dns.RcodeSuccess,
					expectedError: true,
				},
			},
		},
	}
	for _, ttconfig := range tests {
		var got *nameserver
		if ttconfig.expectPanic {
			assert.Panics(t, func() {
				ConfigBuilder(WithClient(ttconfig.client, false), WithTLSVerification(!ttconfig.insecureSkipVerify))
			})
		} else {
			config := ConfigBuilder(WithClient(ttconfig.client, false), WithTLSVerification(!ttconfig.insecureSkipVerify))
			got = newNameserver(ttconfig.hostname, ttconfig.addr, config)
			assert.Equal(t, ttconfig.hostname, got.hostname)
			assert.Equal(t, ttconfig.addr, got.addr)
			// test client
			client := got.defaultDnsClientFactory(ttconfig.client)
			gotType := fmt.Sprintf("%T", client)
			assert.Equal(t, ttconfig.expectedClient, gotType)
		}
		for _, tt := range ttconfig.testCases {
			t.Run(tt.name, func(t *testing.T) {
				msg := new(dns.Msg)
				msg.SetQuestion(dns.Fqdn(tt.qname), dns.TypeA)
				msg.RecursionDesired = tt.rd
				ctx := context.TODO()
				rsp := got.exchange(ctx, msg)

				require.NotNil(t, rsp, "response should not be nil") // it should always return something if qmsg != nil
				if tt.expectedError {
					assert.NotNil(t, rsp.Err)
				} else {
					require.Nil(t, rsp.Err)
					rmsg := rsp.Msg
					require.NotNil(t, rmsg, "rmsg should not be nil")
					assert.Equal(t, tt.rcode, rmsg.Rcode, "rcodes should match")
					assert.Equal(t, tt.expectedNrAnswers, len(rmsg.Answer), "expected a different number of results")
					if len(tt.expectedAnswers) > 0 {
						assert.True(t, matchall(rmsg.Answer, tt.expectedAnswers), "matchall for answers failed")
					}
					if len(tt.expectedAuth) > 0 {
						assert.True(t, matchall(rmsg.Ns, tt.expectedAuth), "matchall for authoritative failed")
					}
					if len(tt.expectedExtra) > 0 {
						assert.True(t, matchall(rmsg.Extra, tt.expectedExtra), "matchall for additional failed")
					}
				}
			})
		}
	}
}
