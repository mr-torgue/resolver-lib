package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mr-torgue/dns"
	"github.com/mr-torgue/resolver-lib/clients"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock DNS Client
type MockDNSClient struct {
	mock.Mock
}

func (m *MockDNSClient) ExchangeContext(ctx context.Context, msg *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	addr = net.JoinHostPort(addr, "53")
	args := m.Called(ctx, msg, addr)
	return args.Get(0).(*dns.Msg), args.Get(1).(time.Duration), args.Error(2)
}

func TestExchange_ValidDNSMessage(t *testing.T) {
	// Setup
	mockClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return mockClient
	}
	ns := &nameserver{addr: "192.0.2.53", dnsClientFactory: factory}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()
	expectedResponse := new(dns.Msg)
	expectedDuration := 10 * time.Millisecond

	// Mock the ExchangeContext function to return the expected response and no error
	mockClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return(expectedResponse, expectedDuration, nil)

	// Execute
	response := ns.exchange(ctx, msg)

	// Assertions
	assert.NoError(t, response.Err)
	assert.Equal(t, expectedResponse, response.Msg)
	assert.Equal(t, expectedDuration, response.Duration)
}

func TestExchange_NilDNSMessage(t *testing.T) {
	// Setup
	mockClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return mockClient
	}
	ns := &nameserver{addr: "192.0.2.53", dnsClientFactory: factory}

	ctx := context.TODO()

	// Execute
	response := ns.exchange(ctx, nil)

	// Assertions
	assert.ErrorIs(t, response.Err, ErrNilMessageSentToExchange)
}

func TestExchange_DNSClientError(t *testing.T) {
	// Setup

	mockClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return mockClient
	}
	ns := &nameserver{addr: "192.0.2.53", dnsClientFactory: factory}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()
	expectedError := errors.New("mock client error")

	// Mock the ExchangeContext function to return an error
	mockClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return((*dns.Msg)(nil), time.Duration(0), expectedError)

	// Execute
	response := ns.exchange(ctx, msg)

	// Assertions
	assert.Error(t, response.Err)
	assert.Equal(t, expectedError, response.Err)
}

func TestExchange_UDPErrorFallbackToTCP(t *testing.T) {
	// Setup
	udpClient := new(MockDNSClient)
	tcpClient := new(MockDNSClient)

	// Define the dnsClientFactory to return the correct client for each protocol
	factory := func(protocol string) dnsClient {
		if protocol == "udp" {
			return udpClient
		}
		return tcpClient
	}
	ns := &nameserver{addr: "192.0.2.53", dnsClientFactory: factory}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()

	expectedResponse := new(dns.Msg)
	expectedDuration := 10 * time.Millisecond

	// Mock the UDP client to return an error, and the TCP client to return a valid response
	udpClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return((*dns.Msg)(nil), time.Duration(0), errors.New("mock UDP error")).Once()
	tcpClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return(expectedResponse, expectedDuration, nil).Once()

	// Execute
	response := ns.exchange(ctx, msg)

	// Assertions
	assert.NoError(t, response.Err)
	assert.Equal(t, expectedResponse, response.Msg)
	assert.Equal(t, expectedDuration, response.Duration)
	udpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
	tcpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
}

func TestExchange_TruncatedResponseFallbackToTCP(t *testing.T) {
	// Setup

	udpClient := new(MockDNSClient)
	tcpClient := new(MockDNSClient)

	// Define the dnsClientFactory to return the correct client for each protocol
	factory := func(protocol string) dnsClient {
		if protocol == "udp" {
			return udpClient
		}
		return tcpClient
	}
	ns := &nameserver{addr: "192.0.2.53", dnsClientFactory: factory}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()

	// Simulate a truncated response for UDP, which will force the function to retry with TCP
	truncatedResponse := &dns.Msg{MsgHdr: dns.MsgHdr{Truncated: true}}
	expectedResponse := new(dns.Msg)
	expectedDuration := 10 * time.Millisecond

	// Mock the UDP client to return a truncated response, and the TCP client to return a valid response
	udpClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return(truncatedResponse, time.Duration(0), nil).Once()
	tcpClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return(expectedResponse, expectedDuration, nil).Once()

	// Execute
	response := ns.exchange(ctx, msg)

	// Assertions
	assert.NoError(t, response.Err)
	assert.Equal(t, expectedResponse, response.Msg)
	assert.Equal(t, expectedDuration, response.Duration)
	udpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
	tcpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
}

func TestExchange_BothUDPAndTCPReturnErrors(t *testing.T) {
	// Setup
	udpClient := new(MockDNSClient)
	tcpClient := new(MockDNSClient)

	// Define the dnsClientFactory to return the correct client for each protocol
	factory := func(protocol string) dnsClient {
		if protocol == "udp" {
			return udpClient
		}
		return tcpClient
	}
	ns := &nameserver{addr: "192.0.2.53", dnsClientFactory: factory}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()

	// Mock both UDP and TCP to return errors
	udpError := errors.New("mock UDP error")
	tcpError := errors.New("mock TCP error")

	udpClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return((*dns.Msg)(nil), time.Duration(0), udpError).Once()
	tcpClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return((*dns.Msg)(nil), time.Duration(0), tcpError).Once()

	// Execute
	response := ns.exchange(ctx, msg)

	// Assertions
	assert.Error(t, response.Err)
	assert.Equal(t, tcpError, response.Err)
	udpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
	tcpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
}

func TestExchange_IPv6AddressFormatting(t *testing.T) {
	// Setup
	mockClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return mockClient
	}

	ns := &nameserver{addr: "2001:db8::1", dnsClientFactory: factory}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()

	expectedResponse := new(dns.Msg)
	expectedDuration := 10 * time.Millisecond

	// Mock the ExchangeContext to return a valid response
	mockClient.On("ExchangeContext", ctx, msg, "[2001:db8::1]:53").Return(expectedResponse, expectedDuration, nil).Once()

	// Execute
	response := ns.exchange(ctx, msg)

	// Assertions
	assert.NoError(t, response.Err)
	assert.Equal(t, expectedResponse, response.Msg)
	assert.Equal(t, expectedDuration, response.Duration)
	mockClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
}

func TestDefaultDnsClientFactory_UDP(t *testing.T) {

	ns := &nameserver{addr: "2001:db8::1"}

	client := ns.defaultDnsClientFactory("udp")
	// changed
	assert.IsType(t, new(clients.ClassicClient), client)
	assert.IsType(t, new(dns.Client), client.(*clients.ClassicClient).Client)
	typedClient, ok := client.(*clients.ClassicClient)
	assert.True(t, ok)
	if ok {
		assert.Equal(t, DefaultTimeoutUDP, typedClient.Client.Timeout)
		assert.Equal(t, "53", typedClient.Port)
	}

}

func TestDefaultDnsClientFactory_TCP(t *testing.T) {

	ns := &nameserver{addr: "2001:db8::1"}

	client := ns.defaultDnsClientFactory("tcp")
	// changed
	assert.IsType(t, new(clients.ClassicClient), client)
	assert.IsType(t, new(dns.Client), client.(*clients.ClassicClient).Client)
	typedClient, ok := client.(*clients.ClassicClient)
	assert.True(t, ok)
	if ok {
		assert.Equal(t, DefaultTimeoutTCP, typedClient.Client.Timeout)
		assert.Equal(t, "53", typedClient.Port)
	}

}

// ---------------------- NEW TESTS

// match returns true if rr is in the expectedRRs slice
func match(rr dns.RR, expectedRRs []ExpectedRR) (bool, int) {
	for i, expectedRR := range expectedRRs {
		if expectedRR.qtype == rr.Header().Rrtype && strings.Contains(rr.String(), expectedRR.value) {
			return true, i
		}
	}
	return false, 0
}

// matchall returns true iff rrs and expectedRRs are the same
func matchall(rrs []dns.RR, expectedRRs []ExpectedRR) bool {
	matchedIndices := make(map[int]bool)
	for _, rr := range rrs {
		matched, index := match(rr, expectedRRs)
		if matched {
			if matchedIndices[index] {
				return false
			}
			matchedIndices[index] = true
		}
	}
	return len(matchedIndices) == len(expectedRRs)
}

type ExpectedRR struct {
	qtype uint16
	value string
}

type TestCase struct {
	name              string
	qname             string
	qtype             uint16
	rcode             int
	rd                bool
	expectedNrAnswers int
	expectedAnswers   []ExpectedRR
	expectedNrAuth    int
	expectedAuth      []ExpectedRR
	expectedNrExtra   int
	expectedExtra     []ExpectedRR
	expectedError     bool
}

// Test_exchange tests the NS exchange function with multiple clients.
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
				SetConfig(ConfigBuilder(WithClient(ttconfig.client, false), WithTLSVerification(!ttconfig.insecureSkipVerify)))
			})
		} else {
			SetConfig(ConfigBuilder(WithClient(ttconfig.client, false), WithTLSVerification(!ttconfig.insecureSkipVerify)))
			got = newNameserver(ttconfig.hostname, ttconfig.addr)
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

// Tests_newNameserver tests if nameservers get created correctly.
func Test_newNameserver(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		hostname           string
		addr               string
		client             string
		expectedClient     string
		insecureSkipVerify bool
		expectPanic        bool
	}{
		{
			name:               "Empty config, should fail",
			hostname:           "",
			addr:               "",
			client:             "",
			insecureSkipVerify: false,
			expectPanic:        true,
		},
		{
			name:               "NS with UDP client",
			hostname:           "name",
			addr:               "1",
			client:             "udp",
			expectedClient:     "*clients.ClassicClient",
			insecureSkipVerify: false,
		},
		{
			name:               "NS with DoQ client",
			hostname:           "name",
			addr:               "1",
			client:             "doq",
			expectedClient:     "*clients.DOQClient",
			insecureSkipVerify: false,
		},
		{
			name:               "NS with DoT client",
			hostname:           "name",
			addr:               "1",
			client:             "dot",
			expectedClient:     "*clients.ClassicClient",
			insecureSkipVerify: false,
		},
		{
			name:               "NS with TCP client",
			hostname:           "name",
			addr:               "1",
			client:             "tcp",
			expectedClient:     "*clients.ClassicClient",
			insecureSkipVerify: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectPanic {
				assert.Panics(t, func() {
					SetConfig(ConfigBuilder(WithClient(tt.client, true), WithTLSVerification(!tt.insecureSkipVerify)))
				})
			} else {
				SetConfig(ConfigBuilder(WithClient(tt.client, true), WithTLSVerification(!tt.insecureSkipVerify)))
				got := newNameserver(tt.hostname, tt.addr)
				assert.Equal(t, tt.hostname, got.hostname)
				assert.Equal(t, tt.addr, got.addr)
				// test client
				client := got.defaultDnsClientFactory(tt.client)
				gotType := fmt.Sprintf("%T", client)
				assert.Equal(t, tt.expectedClient, gotType)

			}
		})
	}
}
