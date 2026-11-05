package resolver

import (
	"crypto/tls"
	"strconv"
	"time"

	"github.com/mr-torgue/dns"
	"github.com/mr-torgue/resolver-lib/cache"
	"github.com/mr-torgue/resolver-lib/log"
)

const (
	DefaultMaxAllowedTTL = uint32(60 * 60 * 48) // 48 Hours

	DefaultMaxQueriesPerRequest = uint32(100)

	DefaultDesireNumberOfNameserversPerZone = 3

	DefaultLazyEnrichment = false

	DefaultSuppressBogusResponseSections = true

	DefaultRemoveAuthoritySectionForPositiveAnswers  = true
	DefaultRemoveAdditionalSectionForPositiveAnswers = true

	DefaultUDPSize    uint16 = 8192
	DefaultTimeoutUDP        = 400 * time.Millisecond
	DefaultTimeoutTCP        = 1000 * time.Millisecond
	DefaultTimeoutDOQ        = 1500 * time.Millisecond
	DefaultTimeoutDOT        = 1500 * time.Millisecond
	DefaultDNSPort           = "53"
	DefaultDoQPort           = "853"
	DefaultDoTPort           = "8853"

	DefaultRootzone    = "named.root"
	DefaultRootanchors = "root-anchors.xml"

	// just some random values. no real thought went into this.
	DefaultTLSCacheSize = 1024
	DefaultCacheSize    = 2048
)

//---

// Cache Default (disabled) cache function.
//var Cache CacheInterface = nil

//---

//type Logger func(string)

// Default logging functions just black-hole the input.

// Log is the package-level default logger. It defaults to doing nothing.
var Log log.Logger = log.NopLogger{}

// SetLogger allows external users to override the package-level default logger.
// It only affects Configs built afterwards (see ConfigBuilder).
func SetLogger(l log.Logger) {
	if l == nil {
		Log = log.NopLogger{}
		return
	}
	Log = l
}

// The Config struct (c) contains the configuration for the resolver.
// It does only do some basic checking.
// At some point, we should move the complete configuration to this struct.

type Config struct {
	rootZoneFile   string
	rootAnchorFile string
	protocols      []string // specifies the clients in order (example: [doq, udp, tcp])
	udpsize        uint16   // we call this udpsize but it is actually the msg size
	// timeout for connections, we need them individually because of fallbacks
	udpTimeout time.Duration
	tcpTimeout time.Duration
	doqTimeout time.Duration
	dotTimeout time.Duration
	dnsPort    string
	doqPort    string
	dotPort    string
	// TLS settings
	tlsCache           tls.ClientSessionCache
	pqcMode            bool // if enabled we only use PQC-safe primitives
	insecureSkipVerify bool // indicates if we check tls or not
	// cache
	cache CacheInterface
	// per-instance behaviour knobs (defaults copied from the package-level vars)
	maxAllowedTTL                             uint32
	maxQueriesPerRequest                      uint32
	desireNumberOfNameserversPerZone          int
	lazyEnrichment                            bool
	suppressBogusResponseSections             bool
	removeAuthoritySectionForPositiveAnswers  bool
	removeAdditionalSectionForPositiveAnswers bool
	// DNSSEC
	trustAnchors []*dns.DS
	// logging
	logger log.Logger
}

// loggerOrDefault returns the instance logger, falling back to the package default.
func (c *Config) loggerOrDefault() log.Logger {
	if c.logger != nil {
		return c.logger
	}
	return Log
}

// DefaultConfig is a working default configuration.
var DefaultConfig = Config{
	rootZoneFile:       DefaultRootzone,
	rootAnchorFile:     DefaultRootanchors,
	protocols:          []string{"udp", "tcp"},
	udpsize:            DefaultUDPSize,
	udpTimeout:         DefaultTimeoutUDP,
	tcpTimeout:         DefaultTimeoutTCP,
	doqTimeout:         DefaultTimeoutDOQ,
	dotTimeout:         DefaultTimeoutDOT,
	dnsPort:            DefaultDNSPort,
	doqPort:            DefaultDoQPort,
	dotPort:            DefaultDoTPort,
	tlsCache:           nil,
	pqcMode:            false,
	insecureSkipVerify: false,
	cache:              nil,
}

type Option func(*Config)

// ConfigBuilder builds a configuration based on the provided options.
// The package-level default variables are snapshotted here; later changes to them
// do not affect the returned Config.
func ConfigBuilder(options ...Option) *Config {
	c := DefaultConfig
	c.maxAllowedTTL = DefaultMaxAllowedTTL
	c.maxQueriesPerRequest = DefaultMaxQueriesPerRequest
	c.desireNumberOfNameserversPerZone = DefaultDesireNumberOfNameserversPerZone
	c.lazyEnrichment = DefaultLazyEnrichment
	c.suppressBogusResponseSections = DefaultSuppressBogusResponseSections
	c.removeAuthoritySectionForPositiveAnswers = DefaultRemoveAuthoritySectionForPositiveAnswers
	c.removeAdditionalSectionForPositiveAnswers = DefaultRemoveAdditionalSectionForPositiveAnswers
	c.logger = Log
	for _, o := range options {
		o(&c)
	}
	return &c
}

// WithMaxAllowedTTL sets the maximum TTL cached for any record.
func WithMaxAllowedTTL(ttl uint32) Option {
	return func(c *Config) { c.maxAllowedTTL = ttl }
}

// WithMaxQueriesPerRequest sets the maximum number of DNS lookups per Exchange call.
func WithMaxQueriesPerRequest(max uint32) Option {
	return func(c *Config) { c.maxQueriesPerRequest = max }
}

// WithDesireNumberOfNameserversPerZone sets how many nameserver addresses a zone pool should try to know.
func WithDesireNumberOfNameserversPerZone(n int) Option {
	return func(c *Config) { c.desireNumberOfNameserversPerZone = n }
}

// WithLazyEnrichment toggles lazy pool enrichment for this instance.
func WithLazyEnrichment(lazy bool) Option {
	return func(c *Config) { c.lazyEnrichment = lazy }
}

// WithSuppressBogusResponseSections toggles suppression of response sections for Bogus answers.
func WithSuppressBogusResponseSections(suppress bool) Option {
	return func(c *Config) { c.suppressBogusResponseSections = suppress }
}

// WithRemoveAuthoritySectionForPositiveAnswers toggles removal of the Authority section for positive answers.
func WithRemoveAuthoritySectionForPositiveAnswers(remove bool) Option {
	return func(c *Config) { c.removeAuthoritySectionForPositiveAnswers = remove }
}

// WithRemoveAdditionalSectionForPositiveAnswers toggles removal of the Additional section for positive answers.
func WithRemoveAdditionalSectionForPositiveAnswers(remove bool) Option {
	return func(c *Config) { c.removeAdditionalSectionForPositiveAnswers = remove }
}

// WithTrustAnchors sets the DNSSEC trust anchors for this instance.
func WithTrustAnchors(anchors []*dns.DS) Option {
	return func(c *Config) { c.trustAnchors = anchors }
}

// WithLogger sets the logger for this instance.
func WithLogger(l log.Logger) Option {
	return func(c *Config) {
		if l == nil {
			c.logger = log.NopLogger{}
			return
		}
		c.logger = l
	}
}

// WithCustomRoot overwrites the standard rootzone and anchors.
func WithCustomRoot(filename string, anchorfilename string) Option {
	return func(c *Config) {
		c.rootZoneFile = filename
		c.rootAnchorFile = anchorfilename
	}
}

// WithClients specifies which client to use.
// Supported: doq, doh, dot, udp, and tcp.
// Fallback can be enabled.
func WithClient(client string, fallback bool) Option {
	return func(c *Config) {
		// check if clients are allowed
		switch client {
		case "udp":
			if fallback {
				c.protocols = []string{"udp", "tcp"}
			} else {
				c.protocols = []string{"udp"}
			}
		case "tcp":
			c.protocols = []string{"tcp"}
		case "dot":
			if fallback {
				c.protocols = []string{"dot", "udp", "tcp"}
			} else {
				c.protocols = []string{"dot"}
			}
		case "doq":
			if fallback {
				c.protocols = []string{"doq", "udp", "tcp"}
			} else {
				c.protocols = []string{"doq"}
			}
		default:
			panic("Only the following clients are supported: udp, tcp, dot, and doq")
		}
	}
}

// WithTLSVerification indicates if TLS verification is enabled.
// In case of clients that don't use TLS, this option is ignored.
func WithTLSVerification(verify bool) Option {
	return func(c *Config) {
		c.insecureSkipVerify = !verify
	}
}

// WithTLSCache indicates the cache size.
func WithTLSCache(capacity int) Option {
	return func(c *Config) {
		if capacity == 0 {
			c.tlsCache = nil
		} else {
			c.tlsCache = tls.NewLRUClientSessionCache(capacity)
		}
	}
}

// WithPQCMode turns the pqc mode on or off.
func WithPQCMode(pqcMode bool) Option {
	return func(c *Config) {
		c.pqcMode = pqcMode
	}
}

// WithCustomDNSPort changes the default port for UDP/TCP.
func WithDNSPort(dnsPort int) Option {
	return func(c *Config) {
		c.dnsPort = strconv.Itoa(dnsPort)
	}
}

// WithCustomDoQPort changes the default port for DoQ.
func WithDoQPort(doqPort int) Option {
	return func(c *Config) {
		c.doqPort = strconv.Itoa(doqPort)
	}
}

// WithCustomDoTPort changes the default port for DoT.
func WithDoTPort(dotPort int) Option {
	return func(c *Config) {
		c.dotPort = strconv.Itoa(dotPort)
	}
}

func WithUDPSize(udpsize uint16) Option {
	return func(c *Config) {
		c.udpsize = udpsize
	}
}

// WithTimeouts sets the timeouts for connections.
func WithTimeouts(udp, tcp, tls, quic time.Duration) Option {
	return func(c *Config) {
		c.udpTimeout = udp
		c.tcpTimeout = tcp
		c.dotTimeout = tls
		c.doqTimeout = quic
	}
}

// WithCache sets the DNS cache. If set to 0, it gets disabled.
// Note: this is the DNS cache, not the TLS session cache.
func WithCache(size int) Option {
	return func(c *Config) {
		if size == 0 {
			c.cache = nil
		} else {
			c.cache = cache.NewCache(cache.WithCapacity(size))
		}
	}
}
