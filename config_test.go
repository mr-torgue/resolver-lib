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
	assert.Equal(t, []string{"udp", "tcp"}, config.protocols)
	assert.Equal(t, DefaultRootanchors, config.rootAnchorFile)
	assert.Equal(t, DefaultRootzone, config.rootZoneFile)
	assert.Equal(t, "udp", config.client)
	assert.Equal(t, DefaultTimeoutUDP, config.udpTimeout)
	assert.Equal(t, DefaultTimeoutTCP, config.tcpTimeout)
	assert.Equal(t, DefaultTimeoutDOQ, config.doqTimeout)
	assert.Equal(t, DefaultTimeoutDOT, config.dotTimeout)
	assert.Equal(t, false, config.insecureSkipVerify)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectPanic {
				assert.Panics(t, func() {
					SetConfig(ConfigBuilder(WithClient(tt.client, tt.fallback), WithCustomRoot(tt.rootzonefile, tt.rootanchor), WithTLSVerification(!tt.insecureSkipVerify)))
				})
			} else {
				SetConfig(ConfigBuilder(WithClient(tt.client, tt.fallback), WithCustomRoot(tt.rootzonefile, tt.rootanchor), WithTLSVerification(!tt.insecureSkipVerify)))
				assert.Equal(t, tt.protocols, config.protocols)
				assert.Equal(t, tt.rootanchor, config.rootAnchorFile)
				assert.Equal(t, tt.rootzonefile, config.rootZoneFile)
				assert.Equal(t, tt.client, config.client)
				assert.Equal(t, DefaultTimeoutUDP, config.udpTimeout)
				assert.Equal(t, DefaultTimeoutTCP, config.tcpTimeout)
				assert.Equal(t, DefaultTimeoutDOQ, config.doqTimeout)
				assert.Equal(t, DefaultTimeoutDOT, config.dotTimeout)
				assert.Equal(t, tt.insecureSkipVerify, config.insecureSkipVerify)
			}
		})
	}
	// test timeout
	SetConfig(ConfigBuilder(WithTimeouts(123, 456, 789, 100)))
	assert.Equal(t, time.Duration(123), config.udpTimeout)
	assert.Equal(t, time.Duration(456), config.tcpTimeout)
	assert.Equal(t, time.Duration(789), config.dotTimeout)
	assert.Equal(t, time.Duration(100), config.doqTimeout)

	SetConfig(&DefaultConfig) // reset config
	assert.Equal(t, []string{"udp", "tcp"}, config.protocols)
	assert.Equal(t, DefaultRootanchors, config.rootAnchorFile)
	assert.Equal(t, DefaultRootzone, config.rootZoneFile)
	assert.Equal(t, "udp", config.client)
	assert.Equal(t, DefaultTimeoutUDP, config.udpTimeout)
	assert.Equal(t, DefaultTimeoutTCP, config.tcpTimeout)
	assert.Equal(t, DefaultTimeoutDOQ, config.doqTimeout)
	assert.Equal(t, DefaultTimeoutDOT, config.dotTimeout)
	assert.Equal(t, false, config.insecureSkipVerify)
}
