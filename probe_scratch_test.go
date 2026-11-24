package resolver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestProbeScratch(t *testing.T) {
	domains := []string{
		"alg13.dnstest.dev", "valid.alg13.dnstest.dev", "invalid.alg13.dnstest.dev",
		"expired.alg13.dnstest.dev", "invalid-dnskey.alg13.dnstest.dev", "expired-dnskey.alg13.dnstest.dev",
		"mldsa44.dnstest.dev", "valid.mldsa44.dnstest.dev", "invalid.mldsa44.dnstest.dev",
		"expired.mldsa44.dnstest.dev", "invalid-dnskey.mldsa44.dnstest.dev", "expired-dnskey.mldsa44.dnstest.dev",
		"dual-valid.mldsa44.dnstest.dev", "upgrade.mldsa44.dnstest.dev", "downgrade.mldsa44.dnstest.dev",
	}
	r := NewResolver(ConfigBuilder(WithClient("udp", true), WithTimeouts(8*time.Second, 8*time.Second, 8*time.Second, 8*time.Second)))
	for _, d := range domains {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(d), dns.TypeA)
		msg.SetEdns0(1232, true)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		resp := r.Exchange(ctx, msg)
		cancel()
		if resp == nil {
			fmt.Printf("PROBE %-38s: nil response\n", d)
			continue
		}
		ans := ""
		if resp.Msg != nil {
			for _, rr := range resp.Msg.Answer {
				if a, ok := rr.(*dns.A); ok {
					ans += a.A.String() + " "
				}
			}
			fmt.Printf("PROBE %-38s: rcode=%d auth=%v ad=%v doe=%v ans=[%s] err=%v dur=%s\n", d, resp.Msg.Rcode, resp.Auth, resp.Msg.AuthenticatedData, resp.Doe, ans, resp.Err, resp.Duration)
		} else {
			fmt.Printf("PROBE %-38s: msg=nil auth=%v err=%v\n", d, resp.Auth, resp.Err)
		}
	}
}
