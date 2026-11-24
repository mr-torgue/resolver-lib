package resolver

import (
	"github.com/miekg/dns"
	"github.com/mr-torgue/resolver-lib/cache"
)

type CacheInterface interface {
	Get(zone string, qmsg *dns.Msg) (*dns.Msg, error)
	Update(zone string, question dns.Question, msg *dns.Msg) error
	// UpdateValidation records the DNSSEC validation outcome of msg on the
	// cache entries that make up the response. It must be called after
	// validation, so that entries are only served as Secure (AD bit) or are
	// removed when Bogus.
	UpdateValidation(zone string, question dns.Question, msg *dns.Msg, status cache.ValidationStatus) error
}
