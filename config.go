package resolver

import (
	"crypto/tls"
	"sync"
	"time"

	"github.com/mr-torgue/resolver-lib/dnssec"
)

const (
	DefaultMaxAllowedTTL = uint32(60 * 60 * 48) // 48 Hours

	DefaultMaxQueriesPerRequest = uint32(100)

	DefaultDesireNumberOfNameserversPerZone = 3

	DefaultLazyEnrichment = false

	DefaultSuppressBogusResponseSections = true

	DefaultRemoveAuthoritySectionForPositiveAnswers  = true
	DefaultRemoveAdditionalSectionForPositiveAnswers = true

	DefaultTimeoutUDP = 400 * time.Millisecond
	DefaultTimeoutTCP = 1000 * time.Millisecond
	DefaultTimeoutDOQ = 1500 * time.Millisecond
	DefaultTimeoutDOT = 1500 * time.Millisecond
	DefaultDNSPort    = 53
	DefaultDoQPort    = 853
	DefaultDoTPort    = 853

	DefaultRootzone    = "named.root"
	DefaultRootanchors = "root-anchors.xml"

	DefaultCacheSize = 1024
)

var (
	// MaxAllowedTTL define the maximum TTL that we'll cache any record for. This overrides any TTLs set by records
	// we receive. Shorter TTLs on received records will still be respected.
	MaxAllowedTTL = DefaultMaxAllowedTTL

	// MaxQueriesPerRequest gives the maximum number of DNS lookups that can occur some a single request to resolver.Exchange().
	// This will include all requests for all the requests from the root, to the leaf; plus any enrichment needed.
	// It's main task is to prevent infinite loops.
	// Note that lookups for DNSKEY and DS records are excluded from this count.
	MaxQueriesPerRequest = DefaultMaxQueriesPerRequest

	// DesireNumberOfNameserversPerZone The number of nameservers, with IP addresses, that we ideally know for a zone.
	// If we know less than this, and LazyEnrichment is _not_ enabled, then we'll set-out to gather more addresses.
	DesireNumberOfNameserversPerZone = DefaultDesireNumberOfNameserversPerZone

	// LazyEnrichment - if true, we put less effort into gathering the IP address details of a zone's nameservers.
	// We will still always gather the minimum to complete the query, but no more.
	// Enabling LazyEnrichment can reduce reliability over multiple queries.
	LazyEnrichment = DefaultLazyEnrichment

	// SuppressBogusResponseSections indicates if a response Answer, Authority and Extra sections should
	// be suppressed if a response is Bogus. The default and recommended value is true which
	// aligns the resolver with https://datatracker.ietf.org/doc/html/rfc4035#section-5.5
	SuppressBogusResponseSections = DefaultSuppressBogusResponseSections

	// RemoveAuthoritySectionForPositiveAnswers indicates if the Authority section should be returned when it's deemed
	// that it's record have no material impact on the result. e.g. it only contains nameserver records.
	RemoveAuthoritySectionForPositiveAnswers  = DefaultRemoveAuthoritySectionForPositiveAnswers
	RemoveAdditionalSectionForPositiveAnswers = DefaultRemoveAdditionalSectionForPositiveAnswers
)

//---

// Cache Default (disabled) cache function.
var Cache CacheInterface = nil

//---

type Logger func(string)

// Default logging functions just black-hole the input.

var Query Logger = func(s string) {}
var Debug Logger = func(s string) {}
var Info Logger = func(s string) {}
var Warn Logger = func(s string) {}

//---

func init() {
	go IPv6Available()
	dnssec.Info = func(s string) {
		Info(s)
	}
	dnssec.Warn = func(s string) {
		Warn(s)
	}
	dnssec.Debug = func(s string) {
		Debug(s)
	}
}

// The Config struct (c) contains the global configuration for the resolver.
// It does only do some basic checking.
// At some point, we should move the complete configuration to this struct.

var (
	GlobalConfig *Config = &DefaultConfig
	mu           sync.Mutex
)

type Config struct {
	rootZoneFile   string
	rootAnchorFile string
	protocols      []string // specifies the clients in order (example: [doq, udp, tcp])
	// timeout for connections, we need them individually because of fallbacks
	udpTimeout time.Duration
	tcpTimeout time.Duration
	doqTimeout time.Duration
	dotTimeout time.Duration
	dnsPort    int
	doqPort    int
	dotPort    int
	// TLS settings
	tlsCache           tls.ClientSessionCache
	pqcMode            bool // if enabled we only use PQC-safe primitives
	insecureSkipVerify bool // indicates if we check tls or not
}

// DefaultConfig is a working default GlobalConfig.
var DefaultConfig = Config{
	rootZoneFile:       DefaultRootzone,
	rootAnchorFile:     DefaultRootanchors,
	protocols:          []string{"udp", "tcp"},
	udpTimeout:         DefaultTimeoutUDP,
	tcpTimeout:         DefaultTimeoutTCP,
	doqTimeout:         DefaultTimeoutDOQ,
	dotTimeout:         DefaultTimeoutDOT,
	insecureSkipVerify: false,
}

type Option func(*Config)

// SetConfig sets the configuration.
// Note
func SetConfig(c *Config) {
	mu.Lock()
	defer mu.Unlock()
	GlobalConfig = c
}

// ConfigBuilder builds a configuration based on the provided options.
func ConfigBuilder(options ...Option) *Config {
	c := DefaultConfig
	for _, o := range options {
		o(&c)
	}
	return &c
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

//func WithTLSCache(int capacity) Option {
//	return func(c *Config) {
//		c.insecureSkipVerify = !verify
//	}
//}

// WithTimeouts sets the timeouts for connections.
func WithTimeouts(udp, tcp, tls, quic time.Duration) Option {
	return func(c *Config) {
		c.udpTimeout = udp
		c.tcpTimeout = tcp
		c.dotTimeout = tls
		c.doqTimeout = quic
	}
}
