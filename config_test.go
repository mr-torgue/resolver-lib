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
		dnsPort            int
		doqPort            int
		dotPort            int
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
	assert.Equal(t, []string{"udp", "tcp"}, GlobalConfig.protocols)
	assert.Equal(t, DefaultRootanchors, GlobalConfig.rootAnchorFile)
	assert.Equal(t, DefaultRootzone, GlobalConfig.rootZoneFile)
	assert.Equal(t, DefaultTimeoutUDP, GlobalConfig.udpTimeout)
	assert.Equal(t, DefaultTimeoutTCP, GlobalConfig.tcpTimeout)
	assert.Equal(t, DefaultTimeoutDOQ, GlobalConfig.doqTimeout)
	assert.Equal(t, DefaultTimeoutDOT, GlobalConfig.dotTimeout)
	assert.Equal(t, DefaultDNSPort, GlobalConfig.dnsPort)
	assert.Equal(t, DefaultDoQPort, GlobalConfig.doqPort)
	assert.Equal(t, DefaultDoTPort, GlobalConfig.dotPort)
	assert.NotNil(t, GlobalConfig.tlsCache)
	assert.False(t, GlobalConfig.pqcMode)
	assert.Equal(t, false, GlobalConfig.insecureSkipVerify)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectPanic {
				assert.Panics(t, func() {
					SetConfig(ConfigBuilder(WithClient(tt.client, tt.fallback), WithCustomRoot(tt.rootzonefile, tt.rootanchor), WithTLSVerification(!tt.insecureSkipVerify)))
				})
			} else {
				SetConfig(ConfigBuilder(WithClient(tt.client, tt.fallback), WithCustomRoot(tt.rootzonefile, tt.rootanchor), WithTLSVerification(!tt.insecureSkipVerify)))
				assert.Equal(t, tt.protocols, GlobalConfig.protocols)
				assert.Equal(t, tt.rootanchor, GlobalConfig.rootAnchorFile)
				assert.Equal(t, tt.rootzonefile, GlobalConfig.rootZoneFile)
				assert.Equal(t, DefaultTimeoutUDP, GlobalConfig.udpTimeout)
				assert.Equal(t, DefaultTimeoutTCP, GlobalConfig.tcpTimeout)
				assert.Equal(t, DefaultTimeoutDOQ, GlobalConfig.doqTimeout)
				assert.Equal(t, DefaultTimeoutDOT, GlobalConfig.dotTimeout)
				assert.Equal(t, tt.insecureSkipVerify, GlobalConfig.insecureSkipVerify)
			}
		})
	}
	// test timeout
	SetConfig(ConfigBuilder(WithTimeouts(123, 456, 789, 100)))
	assert.Equal(t, time.Duration(123), GlobalConfig.udpTimeout)
	assert.Equal(t, time.Duration(456), GlobalConfig.tcpTimeout)
	assert.Equal(t, time.Duration(789), GlobalConfig.dotTimeout)
	assert.Equal(t, time.Duration(100), GlobalConfig.doqTimeout)

	// test custom ports
	SetConfig(ConfigBuilder(WithCustomDNSPort(1234), WithCustomDoQPort(8853), WithCustomDoTPort(153)))
	assert.Equal(t, 1234, GlobalConfig.dnsPort)
	assert.Equal(t, 8853, GlobalConfig.doqPort)
	assert.Equal(t, 153, GlobalConfig.dotPort)

	// test pqc mode
	SetConfig(ConfigBuilder(WithPQCMode(true)))
	assert.True(t, GlobalConfig.pqcMode)

	SetConfig(&DefaultConfig) // reset config
	assert.Equal(t, []string{"udp", "tcp"}, GlobalConfig.protocols)
	assert.Equal(t, DefaultRootanchors, GlobalConfig.rootAnchorFile)
	assert.Equal(t, DefaultRootzone, GlobalConfig.rootZoneFile)
	assert.Equal(t, DefaultTimeoutUDP, GlobalConfig.udpTimeout)
	assert.Equal(t, DefaultTimeoutTCP, GlobalConfig.tcpTimeout)
	assert.Equal(t, DefaultTimeoutDOQ, GlobalConfig.doqTimeout)
	assert.Equal(t, DefaultTimeoutDOT, GlobalConfig.dotTimeout)
	assert.Equal(t, DefaultDNSPort, GlobalConfig.dnsPort)
	assert.Equal(t, DefaultDoQPort, GlobalConfig.doqPort)
	assert.Equal(t, DefaultDoTPort, GlobalConfig.dotPort)
	assert.NotNil(t, GlobalConfig.tlsCache)
	assert.False(t, GlobalConfig.pqcMode)
	assert.Equal(t, false, GlobalConfig.insecureSkipVerify)
}
