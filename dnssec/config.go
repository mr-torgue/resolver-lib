package dnssec

import (
	"encoding/xml"
	"fmt"
	"os"
	"time"

	"github.com/mr-torgue/dns"
	"github.com/mr-torgue/resolver-lib/log"
)

const (
	DefaultRequireAllSignaturesValid = false

	DefaultMaxAllowedTTL = uint32(60 * 60 * 48) // 48 Hours
)

// The package-level variables below are only defaults. They are read once when an
// Authenticator is created (see NewAuth) and are never read at runtime afterwards,
// so concurrent Authenticator instances are fully independent of each other.
var (
	RootTrustAnchors []*dns.DS
	//RootTrustAnchors = anchors.GetValid()

	// RequireAllSignaturesValid
	// If false (default), then one or more RRSIG per RRSET must be valid for the overall state to be valid.
	// If true, _all_ RRSIGs returned must be valid for the overall state to be valid.
	//
	// Note:
	//  https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.3
	//	If other RRSIG RRs also cover this RRset, the local resolver security
	//	policy determines whether the resolver also has to test these RRSIG
	//	RRs and how to resolve conflicts if these RRSIG RRs lead to differing
	//	results.
	RequireAllSignaturesValid = DefaultRequireAllSignaturesValid

	// MaxAllowedTTL define the maximum TTL that we'll calculate for any record. This overrides any TTLs set by records
	// we receive. Shorter TTLs on received records will still be respected.
	MaxAllowedTTL = DefaultMaxAllowedTTL
)

// Log is the package-level default logger. It defaults to doing nothing.
var Log log.Logger = log.NopLogger{}

// SetLogger allows external users to override the package-level default logger.
// It only affects Authenticator instances created afterwards.
func SetLogger(l log.Logger) {
	if l == nil {
		Log = log.NopLogger{}
		return
	}
	Log = l
}

// Config holds the per-instance configuration of an Authenticator.
type Config struct {
	TrustAnchors              []*dns.DS
	MaxAllowedTTL             uint32
	RequireAllSignaturesValid bool
	Logger                    log.Logger
}

// DefaultConfig returns a Config populated from the package-level defaults.
func DefaultConfig() Config {
	return Config{
		TrustAnchors:              RootTrustAnchors,
		MaxAllowedTTL:             MaxAllowedTTL,
		RequireAllSignaturesValid: RequireAllSignaturesValid,
		Logger:                    Log,
	}
}

// Option customises an Authenticator's Config.
type Option func(*Config)

// WithTrustAnchors sets the trust anchors used to start the chain of trust.
func WithTrustAnchors(anchors []*dns.DS) Option {
	return func(c *Config) { c.TrustAnchors = anchors }
}

// WithMaxAllowedTTL sets the maximum TTL calculated for any record.
func WithMaxAllowedTTL(ttl uint32) Option {
	return func(c *Config) { c.MaxAllowedTTL = ttl }
}

// WithRequireAllSignaturesValid sets the signature validation policy.
func WithRequireAllSignaturesValid(requireAll bool) Option {
	return func(c *Config) { c.RequireAllSignaturesValid = requireAll }
}

// WithLogger sets the logger for this instance.
func WithLogger(l log.Logger) Option {
	return func(c *Config) {
		if l == nil {
			c.Logger = log.NopLogger{}
			return
		}
		c.Logger = l
	}
}

// TrustAnchor represents the root XML element.
type TrustAnchor struct {
	XMLName    xml.Name    `xml:"TrustAnchor"`
	ID         string      `xml:"id,attr"`
	Source     string      `xml:"source,attr"`
	Zone       string      `xml:"Zone"`
	KeyDigests []KeyDigest `xml:"KeyDigest"`
}

// KeyDigest represents the KeyDigest elements within the TrustAnchor.
type KeyDigest struct {
	ID         string    `xml:"id,attr"`
	ValidFrom  time.Time `xml:"validFrom,attr"`
	ValidUntil time.Time `xml:"validUntil,attr,omitempty"`
	KeyTag     uint16    `xml:"KeyTag"`
	Algorithm  uint8     `xml:"Algorithm"`
	DigestType uint8     `xml:"DigestType"`
	Digest     string    `xml:"Digest"`
}

// ParseAnchors loads an anchor file and returns the valid trust anchors.
// Unlike LoadAnchors it does not touch any package-level state, so it is safe
// to call concurrently for independent instances.
func ParseAnchors(anchorfile string) ([]*dns.DS, error) {
	f, err := os.Open(anchorfile)
	if err != nil {
		return nil, fmt.Errorf("root anchors file not found: %w", err)
	}
	defer f.Close()

	anchors := []*dns.DS{}

	var ta TrustAnchor
	if err := xml.NewDecoder(f).Decode(&ta); err != nil {
		return nil, fmt.Errorf("failed to decode root anchors: %w", err)
	}

	for _, kd := range ta.KeyDigests {
		// validity check
		now := time.Now()

		// If time t is before this record is valid
		if now.Before(kd.ValidFrom) {
			continue
		}

		// If we have validUntil time, and time t is after it
		if !kd.ValidUntil.IsZero() && now.After(kd.ValidUntil) {
			continue
		}

		ds := &dns.DS{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeDS,
				Class:  dns.ClassINET,
				Ttl:    86400,
			},
			KeyTag:     kd.KeyTag,
			Algorithm:  kd.Algorithm,
			DigestType: kd.DigestType,
			Digest:     kd.Digest,
		}
		anchors = append(anchors, ds)
	}

	return anchors, nil
}

// LoadAnchors loads an anchor file into the package-level RootTrustAnchors.
// Panics if it could not be found or was not parsed correctly.
// Deprecated: use ParseAnchors and WithTrustAnchors for instance-independent anchors.
func LoadAnchors(anchorfile string) {
	anchors, err := ParseAnchors(anchorfile)
	if err != nil {
		panic(err.Error())
	}
	RootTrustAnchors = anchors
}
