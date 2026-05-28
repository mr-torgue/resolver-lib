package dnssec

import (
	"encoding/xml"
	"os"
	"time"

	"github.com/miekg/dns"
)

const (
	DefaultRequireAllSignaturesValid = false

	DefaultMaxAllowedTTL = uint32(60 * 60 * 48) // 48 Hours
)

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

type Logger func(string)

// Default logging functions just black-hole the input.

var Debug Logger = func(s string) {}
var Info Logger = func(s string) {}
var Warn Logger = func(s string) {}

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

// LoadAnchors loads an anchor file into RootTrustAnchors.
// Panics if it could not be found or was not parsed correctly.
func LoadAnchors(anchorfile string) {
	f, err := os.Open(anchorfile)
	if err != nil {
		panic("Root anchors file not found")
	}
	defer f.Close()
	// empty
	RootTrustAnchors = []*dns.DS{}

	var ta TrustAnchor
	if err := xml.NewDecoder(f).Decode(&ta); err != nil {
		panic("Failed to decode root anchors")
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
		RootTrustAnchors = append(RootTrustAnchors, ds)
	}
}
