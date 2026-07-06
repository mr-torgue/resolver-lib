package resolver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSetConfig(t *testing.T) {
	tests := []struct {
		name               string // description of this test case
		rootzonefile       string
		rootanchor         string
		client             string
		protocols          []string
		insecureSkipVerify bool
		pqcMode            bool
		fallback           bool
		expectPanic        bool
	}{
		{
			name:               "Empty client, should panic",
			rootzonefile:       "",
			rootanchor:         "",
			client:             "",
			protocols:          []string{""},
			insecureSkipVerify: false,
			fallback:           true,
			expectPanic:        true,
		},
		{
			name:               "TCP Client",
			rootzonefile:       "anotherrandomvalue",
			rootanchor:         "somerandomvalue",
			client:             "tcp",
			protocols:          []string{"tcp"},
			insecureSkipVerify: false,
			fallback:           true,
		},
		{
			name:               "UDP Client",
			rootzonefile:       "another-randomvalue",
			rootanchor:         "some-randomvalue",
			client:             "udp",
			protocols:          []string{"udp", "tcp"},
			insecureSkipVerify: true,
			fallback:           true,
		},
		{
			name:               "DoQ Client",
			rootzonefile:       "another-randomvalue",
			rootanchor:         "some-randomvalue",
			client:             "doq",
			protocols:          []string{"doq", "udp", "tcp"},
			insecureSkipVerify: true,
			fallback:           true,
		},
		{
			name:               "DoT Client",
			rootzonefile:       "another-randomvalue",
			rootanchor:         "some-randomvalue",
			client:             "dot",
			protocols:          []string{"dot", "udp", "tcp"},
			insecureSkipVerify: true,
			fallback:           true,
		},
		{
			name:               "DoT Client with typo",
			rootzonefile:       "another-randomvalue",
			rootanchor:         "some-randomvalue",
			client:             "d0t",
			protocols:          []string{"dot", "udp", "tcp"},
			insecureSkipVerify: true,
			expectPanic:        true,
			fallback:           true,
		},
		{
			name:               "DoT Client with upper case",
			rootzonefile:       "another-randomvalue",
			rootanchor:         "some-randomvalue",
			client:             "Dot",
			protocols:          []string{"dot", "udp", "tcp"},
			insecureSkipVerify: true,
			expectPanic:        true,
			fallback:           true,
		},
		{
			name:               "DoT Client with no fallback",
			rootzonefile:       "another-randomvalue12",
			rootanchor:         "some-randomvalue2",
			client:             "dot",
			protocols:          []string{"dot"},
			insecureSkipVerify: true,
			fallback:           false,
		},
		{
			name:               "DoQ Client with no fallback",
			rootzonefile:       "another-randomvalue12",
			rootanchor:         "some-randomvalue2",
			client:             "doq",
			protocols:          []string{"doq"},
			insecureSkipVerify: true,
			fallback:           false,
		},
	}
	// test default config
	res := NewResolver(ConfigBuilder())
	assert.Equal(t, []string{"udp", "tcp"}, res.config.protocols)
	assert.Equal(t, DefaultRootanchors, res.config.rootAnchorFile)
	assert.Equal(t, DefaultRootzone, res.config.rootZoneFile)
	assert.Equal(t, DefaultUDPSize, res.config.udpsize)
	assert.Equal(t, DefaultTimeoutUDP, res.config.udpTimeout)
	assert.Equal(t, DefaultTimeoutTCP, res.config.tcpTimeout)
	assert.Equal(t, DefaultTimeoutDOQ, res.config.doqTimeout)
	assert.Equal(t, DefaultTimeoutDOT, res.config.dotTimeout)
	assert.Equal(t, DefaultDNSPort, res.config.dnsPort)
	assert.Equal(t, DefaultDoQPort, res.config.doqPort)
	assert.Equal(t, DefaultDoTPort, res.config.dotPort)
	assert.Nil(t, res.config.tlsCache)
	assert.False(t, res.config.pqcMode)
	assert.Equal(t, false, res.config.insecureSkipVerify)
	assert.Nil(t, res.config.cache)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectPanic {
				assert.Panics(t, func() {
					ConfigBuilder(WithClient(tt.client, tt.fallback), WithCustomRoot(tt.rootzonefile, tt.rootanchor), WithTLSVerification(!tt.insecureSkipVerify))
				})
			} else {
				config := ConfigBuilder(WithClient(tt.client, tt.fallback), WithCustomRoot(tt.rootzonefile, tt.rootanchor), WithTLSVerification(!tt.insecureSkipVerify))
				assert.Equal(t, tt.protocols, config.protocols)
				assert.Equal(t, tt.rootanchor, config.rootAnchorFile)
				assert.Equal(t, tt.rootzonefile, config.rootZoneFile)
				assert.Equal(t, DefaultTimeoutUDP, config.udpTimeout)
				assert.Equal(t, DefaultTimeoutTCP, config.tcpTimeout)
				assert.Equal(t, DefaultTimeoutDOQ, config.doqTimeout)
				assert.Equal(t, DefaultTimeoutDOT, config.dotTimeout)
				assert.Equal(t, tt.insecureSkipVerify, config.insecureSkipVerify)
			}
		})
	}
	// test timeout
	res = NewResolver(ConfigBuilder(WithTimeouts(123, 456, 789, 100)))
	assert.Equal(t, time.Duration(123), res.config.udpTimeout)
	assert.Equal(t, time.Duration(456), res.config.tcpTimeout)
	assert.Equal(t, time.Duration(789), res.config.dotTimeout)
	assert.Equal(t, time.Duration(100), res.config.doqTimeout)

	// test custom ports
	res = NewResolver(ConfigBuilder(WithDNSPort(1234), WithDoQPort(8853), WithDoTPort(153)))
	assert.Equal(t, "1234", res.config.dnsPort)
	assert.Equal(t, "8853", res.config.doqPort)
	assert.Equal(t, "153", res.config.dotPort)

	// test pqc mode
	res = NewResolver(ConfigBuilder(WithPQCMode(true)))
	assert.True(t, res.config.pqcMode)

	// test udpsize
	res = NewResolver(ConfigBuilder(WithUDPSize(12345)))
	assert.Equal(t, uint16(12345), res.config.udpsize)

	// test DNS cache
	res = NewResolver(ConfigBuilder(WithCache(1234)))
	assert.NotNil(t, res.config.cache)
	res = NewResolver(ConfigBuilder(WithCache(0)))
	assert.Nil(t, res.config.cache)

	// test TLS session cache
	res = NewResolver(ConfigBuilder(WithTLSCache(4444)))
	assert.NotNil(t, res.config.tlsCache)
	res = NewResolver(ConfigBuilder(WithTLSCache(0)))
	assert.Nil(t, res.config.tlsCache)

	res = NewResolver(&DefaultConfig) // reset config
	assert.Equal(t, []string{"udp", "tcp"}, res.config.protocols)
	assert.Equal(t, DefaultRootanchors, res.config.rootAnchorFile)
	assert.Equal(t, DefaultRootzone, res.config.rootZoneFile)
	assert.Equal(t, DefaultUDPSize, res.config.udpsize)
	assert.Equal(t, DefaultTimeoutUDP, res.config.udpTimeout)
	assert.Equal(t, DefaultTimeoutTCP, res.config.tcpTimeout)
	assert.Equal(t, DefaultTimeoutDOQ, res.config.doqTimeout)
	assert.Equal(t, DefaultTimeoutDOT, res.config.dotTimeout)
	assert.Equal(t, DefaultDNSPort, res.config.dnsPort)
	assert.Equal(t, DefaultDoQPort, res.config.doqPort)
	assert.Equal(t, DefaultDoTPort, res.config.dotPort)
	assert.Nil(t, res.config.tlsCache)
	assert.False(t, res.config.pqcMode)
	assert.Equal(t, false, res.config.insecureSkipVerify)
	assert.Nil(t, res.config.cache)
}
