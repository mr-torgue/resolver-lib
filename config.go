package resolver

import (
	"crypto/tls"
	"strconv"
	"time"

	// the unsafe package is required for the //go:linkname directive.
	"unsafe"

	"github.com/mr-torgue/resolver-lib/cache"
	"github.com/mr-torgue/resolver-lib/dnssec"
)

var _ = unsafe.Pointer(nil) // this line ensures the unsafe package is not removed.

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
	DefaultDoTPort           = "853"

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
//var Cache CacheInterface = nil

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
}

// DefaultConfig is a working default GlobalConfig.
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
	tlsCache:           tls.NewLRUClientSessionCache(DefaultCacheSize),
	pqcMode:            false,
	insecureSkipVerify: false,
	cache:              nil,
}

type Option func(*Config)

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

// WithTLSCache indicates the cache size.
func WithTLSCache(capacity int) Option {
	return func(c *Config) {
		c.tlsCache = tls.NewLRUClientSessionCache(capacity)
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

func WithCache(size int) Option {
	return func(c *Config) {
		c.cache = cache.NewCache(cache.WithCapacity(size))
	}
}

// BAD CODE WARNING!
// linking not recommmended but it is the easiest way to enforce the use of AES256.
// AES128 should be quantum-safe, but some people are squeamish about the 64 bits of security...

//go:linkname defaultCipherSuitesTLS13
var defaultCipherSuitesTLS13 = []uint16{
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_CHACHA20_POLY1305_SHA256,
}

//go:linkname defaultCipherSuitesTLS13NoAES
var defaultCipherSuitesTLS13NoAES = []uint16{
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_AES_128_GCM_SHA256,
}
