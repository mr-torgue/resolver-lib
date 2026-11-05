package resolver

import (
	"context"
	"fmt"
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
			go func() {
				enrichPool(ctx, name, pool, exchanger, config)
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

	config.loggerOrDefault().Debugf("new zone created [%s]", name)

	// TODO: It would be good if we validated, via DNSSEC, nameserver details. Perhaps we could go do this.
	// And use low TTLs until it's done.

	return z, nil
}

func enrichPool(ctx context.Context, zoneName string, pool *nameserverPool, exchanger exchanger, config *Config) error {
	logger := config.loggerOrDefault()

	hosts := pool.hostnamesWithoutAddresses()
	if len(hosts) == 0 {
		return fmt.Errorf("%w [%s]: the nameserver pool is empty so we have no hostnames to enrich", ErrFailedEnrichingPool, zoneName)
	}

	if len(hosts) > config.desireNumberOfNameserversPerZone {
		hosts = hosts[:config.desireNumberOfNameserversPerZone]
	}

	types := make([]uint16, 0, 2)
	types = append(types, dns.TypeA)
	if IPv6Available() {
		types = append(types, dns.TypeAAAA)
	}

	//---

	// done is buffered so the worker can always send its result and exit,
	// even if we have already stopped waiting (timeout / cancelled context).
	done := make(chan bool, 1)
	go func() {
		doneCalled := false
		for _, t := range types {
			for _, domain := range hosts {
				// Stop early if the caller is no longer interested.
				if ctx.Err() != nil {
					return
				}

				qmsg := new(dns.Msg)
				qmsg.SetQuestion(dns.Fqdn(domain), t)

				response := exchanger.exchange(ctx, qmsg)
				if !response.HasError() && !response.IsEmpty() && len(response.Msg.Answer) > 0 {
					// enrich if the response is good.
					pool.enrich(response.Msg.Answer)
					if !doneCalled {
						done <- true
						doneCalled = true
					}
				}
			}
		}
	}()

	select {
	case <-done:
		switch pool.status() {
		case PoolPrimed:
		case PrimedButNeedsEnhancing:
		default:
			return fmt.Errorf("%w [%s]: the nameserver pool still not primed after enrichment", ErrFailedEnrichingPool, zoneName)
		}
	case <-ctx.Done():
		return fmt.Errorf("%w [%s]: enrichment cancelled: %w", ErrFailedEnrichingPool, zoneName, ctx.Err())
	case <-time.After(3 * time.Second):
		return fmt.Errorf("%w [%s]: enrichment timeout", ErrFailedEnrichingPool, zoneName)
	}

	logger.Debugf("zone pool enriched for [%s]", zoneName)

	return nil
}
