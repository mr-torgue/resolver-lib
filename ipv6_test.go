package resolver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIPv6Available_VerdictIsProcessGlobal shows that the IPv6 probe runs at
// most once per process (sync.Once) and its verdict is latched in package
// globals: whichever test builds the first nameserver pool decides for every
// later test in the same `go test` process. This is why a live test can pass
// when run alone but fail in a full `go test` run.
func TestIPv6Available_VerdictIsProcessGlobal(t *testing.T) {
	oldAvailable, oldAnswered := ipv6Available.Load(), ipv6Answered.Load()
	t.Cleanup(func() {
		ipv6Available.Store(oldAvailable)
		ipv6Answered.Store(oldAnswered)
	})

	ipv6Answered.Store(true)
	ipv6Available.Store(true)
	assert.True(t, IPv6Available(), "a latched true verdict is reported to every caller in the process")

	ipv6Available.Store(false)
	assert.False(t, IPv6Available(), "a latched false verdict is reported to every caller; no re-probe happens")
}
