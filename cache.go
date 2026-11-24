package resolver

import (
	"github.com/miekg/dns"
	"github.com/mr-torgue/resolver-lib/cache"
)

type CacheInterface interface {
	Get(qmsg *dns.Msg) (*dns.Msg, error)
	// Update inserts msg into the cache with the validation status that was
	// determined for it (Indeterminate when no validation was performed).
	// It is called once, after validation. A Bogus status evicts any existing
	// entries instead of caching: bogus data must never be served.
	Update(question dns.Question, msg *dns.Msg, status cache.ValidationStatus) error
}
