package doe

import (
	"github.com/mr-torgue/dns"
)

const zoneName = "example.com."

func newRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}
