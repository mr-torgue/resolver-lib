package resolver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mr-torgue/dns"
)

func createZone(ctx context.Context, name, parent string, nameservers []*dns.NS, extra []dns.RR, exchanger exchanger, config *Config) (zone, error) {
	name = dns.CanonicalName(name)
	parent = dns.CanonicalName(parent)

	if name == parent || !dns.IsSubDomain(parent, name) {
		return nil, fmt.Errorf("%w: the new zone name [%s] must be a subdomain of the parent [%s]", ErrFailedCreatingZoneAndPool, name, parent)
	}

	//---

	pool := newNameserverPool(nameservers, extra, config)

	switch pool.status() {
	case PrimedButNeedsEnhancing:
		if !config.lazyEnrichment {
			// Detach from the request context so caller cancellation does not abort background priming
			bgCtx := context.WithoutCancel(ctx)
			go func() {
				if err := enrichPool(bgCtx, name, pool, exchanger, config); err != nil {
					Log.Warningf("background enrichment failed for [%s]: %v", name, err)
				}
			}()
		}
	case PoolPrimed:
		// Happy days - nothing to do
	case PoolHasHostnamesButNoIpAddresses:
		err := enrichPool(ctx, name, pool, exchanger, config)
		if err != nil {
			return nil, err
		}
	default:
		// Covers PoolEmpty
		return nil, fmt.Errorf("%w for [%s]: the nameserver pool is empty and we have no hostnames to enrich", ErrFailedCreatingZoneAndPool, name)
	}

	z := &zoneImpl{
		zoneName:   name,
		parentName: parent,
		pool:       pool,
		config:     config,
	}

	Log.Debugf("new zone created [%s]", name)

	// TODO: It would be good if we validated, via DNSSEC, nameserver details. Perhaps we could go do this.
	// And use low TTLs until it's done.

	return z, nil
}

func enrichPool(ctx context.Context, zoneName string, pool *nameserverPool, exchanger exchanger, config *Config) error {
	pool.updating.RLock()
	rawHosts := pool.hostsWithoutAddresses
	pool.updating.RUnlock()

	if len(rawHosts) == 0 {
		return fmt.Errorf("%w [%s]: the nameserver pool is empty so we have no hostnames to enrich", ErrFailedEnrichingPool, zoneName)
	}

	limit := len(rawHosts)
	if limit > config.desireNumberOfNameserversPerZone {
		limit = config.desireNumberOfNameserversPerZone
	}

	// Copy slice to avoid race conditions with the pool's internal slice
	hosts := make([]string, limit)
	copy(hosts, rawHosts[:limit])

	types := []uint16{dns.TypeA}
	if IPv6Available() {
		types = append(types, dns.TypeAAAA)
	}

	// Bound enrichment to a maximum of 3 seconds or the caller context
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Concurrently query each host and record type
	for _, domain := range hosts {
		for _, qType := range types {
			wg.Add(1)
			go func(d string, t uint16) {
				defer wg.Done()

				qmsg := new(dns.Msg)
				qmsg.SetQuestion(dns.Fqdn(d), t)

				response := exchanger.exchange(ctx, qmsg)
				if !response.HasError() && !response.IsEmpty() && len(response.Msg.Answer) > 0 {
					pool.enrich(response.Msg.Answer)
				}
			}(domain, qType)
		}
	}

	// Wait for all queries to finish or context to abort
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All queries finished (success or failure)
	case <-ctx.Done():
		return fmt.Errorf("%w [%s]: enrichment timed out or canceled: %w", ErrFailedEnrichingPool, zoneName, ctx.Err())
	}

	// Validate final pool status
	switch pool.status() {
	case PoolPrimed, PrimedButNeedsEnhancing:
		Log.Debugf("zone pool enriched for [%s]", zoneName)
		return nil
	default:
		return fmt.Errorf("%w [%s]: the nameserver pool still not primed after enrichment", ErrFailedEnrichingPool, zoneName)
	}
}
