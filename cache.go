package resolver

import "github.com/mr-torgue/dns"

type CacheInterface interface {
	Get(zone string, question dns.Question) (*dns.Msg, error)
	Update(zone string, question dns.Question, msg *dns.Msg) error
}
