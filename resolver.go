package resolver

import (
	"context"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/mr-torgue/resolver-lib/dnssec"
)

type Resolver struct {
	zones  zoneStore
	funcs  resolverFunctions
	config *Config

	// lifecycle is cancelled by Shutdown and governs background work (e.g.
	// nameserver pool enrichment). It is never derived from a request context.
	lifecycle context.Context
	cancel    context.CancelFunc
}

// The core, top level, resolving functions. They're defined as variables to aid overriding them for testing.
type resolverFunctions struct {
	resolveLabel         func(ctx context.Context, d *domain, z zone, qmsg *dns.Msg, auth *authenticator) (zone, *Response)
	checkForMissingZones func(ctx context.Context, d *domain, z zone, rmsg *dns.Msg, auth *authenticator) zone
	createZone           func(ctx context.Context, name, parent string, nameservers []*dns.NS, extra []dns.RR, exchanger exchanger, config *Config) (zone, error)
	finaliseResponse     func(ctx context.Context, auth *authenticator, qmsg *dns.Msg, response *Response) *Response
	processDelegation    func(ctx context.Context, z zone, rmsg *dns.Msg) (zone, *Response)
	cname                func(ctx context.Context, qmsg *dns.Msg, r *Response, exchanger exchanger, udpsize uint16) error
	getExchanger         func() exchanger
}

func NewResolver(config *Config) *Resolver {
	// load files; anchors are kept on this instance's config, not in package-level state
	anchors, err := dnssec.ParseAnchors(config.rootAnchorFile)
	if err != nil {
		panic(err)
	}
	config.trustAnchors = anchors

	rootZone, err := os.ReadFile(config.rootZoneFile)
	if err != nil {
		panic(err)
	}
	rootZoneStr := string(rootZone)
	pool, err := buildRootServerPool(rootZoneStr, config)
	if err != nil {
		// Everything is technically static at this point.
		panic(err)
	}

	z := new(zones)
	z.add(&zoneImpl{
		zoneName: ".",
		pool:     pool,
		config:   config,
	})

	lifecycle, cancel := context.WithCancel(context.Background())

	resolver := &Resolver{
		zones:     z,
		config:    config,
		lifecycle: lifecycle,
		cancel:    cancel,
	}

	// When not testing, we point to the concrete instances of the functions.
	resolver.funcs = resolverFunctions{
		resolveLabel:         resolver.resolveLabel,
		checkForMissingZones: resolver.checkForMissingZones,
		createZone:           resolver.createZone,
		finaliseResponse:     resolver.finaliseResponse,
		processDelegation:    resolver.processDelegation,
		cname:                cname,
		getExchanger:         resolver.getExchanger,
	}

	return resolver
}

// Shutdown stops background work started by this resolver, such as nameserver
// pool enrichment. In-flight Exchange calls keep running under their caller's
// context. Shutdown is idempotent and safe on a Resolver not built by NewResolver.
func (resolver *Resolver) Shutdown() {
	if resolver.cancel != nil {
		resolver.cancel()
	}
}

// createZone adapts the package-level createZone to this resolver: background
// enrichment runs on the resolver's lifecycle context (stopped by Shutdown)
// rather than on the per-request context.
func (resolver *Resolver) createZone(ctx context.Context, name, parent string, nameservers []*dns.NS, extra []dns.RR, exchanger exchanger, config *Config) (zone, error) {
	bgCtx := resolver.lifecycle
	if bgCtx == nil {
		bgCtx = context.Background()
	}
	return createZone(ctx, bgCtx, name, parent, nameservers, extra, exchanger, config)
}

func (resolver *Resolver) getExchanger() exchanger {
	return resolver
}

// CountZones metrics gathering.
func (resolver *Resolver) CountZones() int {
	return resolver.zones.count()
}

//-----------------------------------------------------------------------------

func buildRootServerPool(rootZone string, config *Config) (*nameserverPool, error) {
	zp := dns.NewZoneParser(strings.NewReader(rootZone), ".", "local")

	pool := &nameserverPool{hostsWithoutAddresses: make([]string, 0), config: config}

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch rr := rr.(type) {
		case *dns.A:
			pool.ipv4 = append(pool.ipv4, newNameserver(rr.Header().Name, rr.A.String(), config))
		case *dns.AAAA:
			pool.ipv6 = append(pool.ipv6, newNameserver(rr.Header().Name, rr.AAAA.String(), config))
		default:
			// Continue
		}
	}

	if err := zp.Err(); err != nil {
		return nil, err
	}

	pool.updateIPCount()

	return pool, nil
}
