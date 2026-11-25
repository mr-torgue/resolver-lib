package resolver

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type NameserverPoolStatus uint8

const (
	PoolEmpty NameserverPoolStatus = iota
	PoolExpired
	PoolHasHostnamesButNoIpAddresses
	PrimedButNeedsEnhancing
	PoolPrimed
)

type nameserverPool struct {
	// hostsWithoutAddresses contains the hostnames of nameservers for which
	// no address has been seen yet. Once an address is found (any family),
	// they're removed from this list. Together with addressesByHostname it
	// decides whether a hostname is one of this zone's nameservers (and thus
	// eligible for enrichment), so no separate list of all nameserver
	// hostnames needs to be kept.
	hostsWithoutAddresses []string

	// addressesByHostname indexes the addresses stored in the pool:
	// hostname -> set of addresses (both families, in string form). It is
	// kept in sync with the ipv4 / ipv6 slices by addAddress(), and gives
	// O(1) membership and duplicate checks, instead of scanning the pool.
	// Guarded by updating (or built before the pool is published).
	addressesByHostname map[string]map[string]struct{}

	ipv4      []exchanger
	ipv4Next  atomic.Uint32
	ipv4Count atomic.Uint32

	ipv6      []exchanger
	ipv6Next  atomic.Uint32
	ipv6Count atomic.Uint32

	updating sync.RWMutex
	enriched sync.Once

	expires atomic.Int64

	config *Config // make sure that this config points to the same as resolver
}

func (pool *nameserverPool) hasIPv4() bool {
	return pool.countIPv4() > 0
}

func (pool *nameserverPool) hasIPv6() bool {
	return pool.countIPv6() > 0
}

func (pool *nameserverPool) countIPv4() uint32 {
	return pool.ipv4Count.Load()
}

func (pool *nameserverPool) countIPv6() uint32 {
	return pool.ipv6Count.Load()
}

func (pool *nameserverPool) getIPv4() exchanger {
	if pool.hasIPv4() {
		// Increments to the next server each time.
		// There's a race condition here, but the outcome isn't "important" enough to warrant locking.
		ipv4Next := pool.ipv4Next.Load() % pool.countIPv4()
		pool.ipv4Next.Store(ipv4Next + 1)

		var ex exchanger
		pool.updating.RLock()
		if int(ipv4Next) < len(pool.ipv4) {
			ex = pool.ipv4[ipv4Next]
		}
		pool.updating.RUnlock()
		return ex
	}
	return nil
}

func (pool *nameserverPool) getIPv6() exchanger {
	if pool.hasIPv6() {
		// Increments to the next server each time.
		// There's a race condition here, but the outcome isn't "important" enough to warrant locking.
		ipv6Next := pool.ipv6Next.Load() % pool.countIPv6()
		pool.ipv6Next.Store(ipv6Next + 1)

		var ex exchanger
		pool.updating.RLock()
		if int(ipv6Next) < len(pool.ipv6) {
			ex = pool.ipv6[ipv6Next]
		}
		pool.updating.RUnlock()
		return ex
	}
	return nil
}

//---

func (pool *nameserverPool) expired() bool {
	expires := pool.expires.Load()
	return expires > 0 && expires < time.Now().Unix()
}

func (pool *nameserverPool) status() NameserverPoolStatus {
	pool.updating.RLock()
	defer pool.updating.RUnlock()

	ipv4Count := len(pool.ipv4)
	ipv6Count := len(pool.ipv6)

	if ipv4Count == 0 && ipv6Count == 0 && len(pool.hostsWithoutAddresses) == 0 {
		return PoolEmpty
	}

	total := ipv4Count
	if IPv6Available() {
		total = total + ipv6Count
	}

	if total == 0 {
		return PoolHasHostnamesButNoIpAddresses
	}

	// If there are unknown addresses, and we have less than x IPs, then we want to enrich.
	if total < pool.config.desireNumberOfNameserversPerZone && len(pool.hostsWithoutAddresses) > 0 {
		return PrimedButNeedsEnhancing
	}

	return PoolPrimed
}

func newNameserverPool(nameservers []*dns.NS, extra []dns.RR, config *Config) *nameserverPool {
	pool := &nameserverPool{config: config}

	var ttl = pool.config.maxAllowedTTL
	pool.hostsWithoutAddresses = make([]string, 0, len(nameservers))

	for _, rr := range nameservers {
		hostname := canonicalName(rr.Ns)

		ttl = min(rr.Header().Ttl, ttl)

		//---

		a, aaaa, minTtlSeen := findAddressesForHostname(hostname, extra, pool.config.maxAllowedTTL)

		if len(a) == 0 && len(aaaa) == 0 {
			pool.hostsWithoutAddresses = append(pool.hostsWithoutAddresses, hostname)
			continue
		}

		//---

		ttl = min(minTtlSeen, ttl)

		for _, addr := range a {
			pool.addAddress(hostname, addr.A.String(), false)
		}

		for _, addr := range aaaa {
			pool.addAddress(hostname, addr.AAAA.String(), true)
		}

	}

	pool.hostsWithoutAddresses = slices.Clip(pool.hostsWithoutAddresses)

	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	pool.expires.Store(expires.Unix())

	pool.updateIPCount()

	return pool
}

// enrich adds address records for this zone's nameservers to the pool.
// Records are accepted regardless of the order in which the A/AAAA responses
// arrive: a hostname is one of this zone's nameservers if it is still pending
// (hostsWithoutAddresses) or if we already store an address for it. Without
// this, a hostname was removed from hostsWithoutAddresses as soon as one
// address family was found, silently discarding the other family's records
// that arrived later (e.g. leaving a zone with IPv6-only nameservers, which
// are unreachable on hosts without IPv6 connectivity).
func (pool *nameserverPool) enrich(records []dns.RR) {
	if len(records) == 0 {
		return
	}

	pool.updating.Lock()
	defer pool.updating.Unlock()

	var ttl = pool.config.maxAllowedTTL

	for _, rr := range records {
		var addrString string
		ipv6Record := false

		switch addr := rr.(type) {
		case *dns.A:
			addrString = addr.A.String()
		case *dns.AAAA:
			addrString = addr.AAAA.String()
			ipv6Record = true
		default:
			continue
		}

		hostname := canonicalName(rr.Header().Name)
		if !pool.nameserverHostnameKnown(hostname) {
			// Not one of this zone's nameservers.
			continue
		}

		if pool.hostAddressKnown(hostname, addrString) {
			// The hostname already has this address.
			continue
		}

		pool.addAddress(hostname, addrString, ipv6Record)

		ttl = min(rr.Header().Ttl, ttl)
	}

	// Any pending hostname that now has at least one address is no longer pending.
	pool.hostsWithoutAddresses = slices.Clip(slices.DeleteFunc(pool.hostsWithoutAddresses, pool.hostResolved))

	if pool.expires.Load() > 0 {
		expires := time.Now().Add(time.Duration(ttl) * time.Second)
		pool.expires.Store(expires.Unix())
	}

	pool.updateIPCount()
}

// addAddress stores an address for a nameserver hostname in the pool, adding
// it to the ipv4 / ipv6 slices AND to the addressesByHostname index. Callers
// must hold updating, or not have published the pool yet.
func (pool *nameserverPool) addAddress(hostname, addr string, ipv6Address bool) {
	if pool.addressesByHostname == nil {
		pool.addressesByHostname = make(map[string]map[string]struct{})
	}
	if _, ok := pool.addressesByHostname[hostname]; !ok {
		pool.addressesByHostname[hostname] = make(map[string]struct{})
	}
	pool.addressesByHostname[hostname][addr] = struct{}{}

	if ipv6Address {
		pool.ipv6 = append(pool.ipv6, newNameserver(hostname, addr, pool.config))
	} else {
		pool.ipv4 = append(pool.ipv4, newNameserver(hostname, addr, pool.config))
	}
}

// hostResolved reports whether hostname has at least one address in the pool.
func (pool *nameserverPool) hostResolved(hostname string) bool {
	_, resolved := pool.addressesByHostname[hostname]
	return resolved
}

// nameserverHostnameKnown reports whether hostname belongs to this zone's
// nameservers, without keeping a separate list of them: it is either still
// waiting for its first address, or we already store an address for it (in
// which case the other address family can still be added).
func (pool *nameserverPool) nameserverHostnameKnown(hostname string) bool {
	for _, pending := range pool.hostsWithoutAddresses {
		if pending == hostname {
			return true
		}
	}
	_, addressed := pool.addressesByHostname[hostname]
	return addressed
}

// hostAddressKnown reports whether hostname already has the given address in
// the pool. An empty addr matches any address of the hostname.
func (pool *nameserverPool) hostAddressKnown(hostname, addr string) bool {
	addresses, addressed := pool.addressesByHostname[hostname]
	if !addressed {
		return false
	}
	if addr == "" {
		return true
	}
	_, known := addresses[addr]
	return known
}

func (pool *nameserverPool) updateIPCount() {
	pool.ipv4Count.Store(uint32(len(pool.ipv4)))
	pool.ipv6Count.Store(uint32(len(pool.ipv6)))
}

func findAddressesForHostname(hostname string, records []dns.RR, maxAllowedTTL uint32) ([]*dns.A, []*dns.AAAA, uint32) {
	a := make([]*dns.A, 0, len(records))
	aaaa := make([]*dns.AAAA, 0, len(records))

	var ttl = maxAllowedTTL

	for _, rr := range records {
		if canonicalName(rr.Header().Name) != hostname {
			continue
		}
		switch addr := rr.(type) {
		case *dns.A:
			a = append(a, addr)
			ttl = min(rr.Header().Ttl, ttl)
		case *dns.AAAA:
			aaaa = append(aaaa, addr)
			ttl = min(rr.Header().Ttl, ttl)
		}
	}

	return a, aaaa, ttl
}
