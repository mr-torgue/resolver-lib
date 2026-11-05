package resolver

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/mr-torgue/dns"
	"github.com/mr-torgue/resolver-lib/dnssec"
)

type authenticator struct {
	ctx  context.Context
	auth *dnssec.Authenticator

	// sendMu guards queue, closed and every wg.Add, so wg.Wait in close never
	// races with an Add. start() drains queue without holding sendMu.
	sendMu sync.Mutex
	queue  chan authenticatorInput
	closed bool
	wg     sync.WaitGroup

	// errMu guards errors, which start() appends to and result() reads after close().
	errMu  sync.Mutex
	errors []error
}

type authenticatorInput struct {
	z   zone
	msg *dns.Msg
}

func newAuthenticator(ctx context.Context, question dns.Question, config *Config) *authenticator {
	a := dnssec.NewAuth(ctx, question,
		dnssec.WithTrustAnchors(config.trustAnchors),
		dnssec.WithMaxAllowedTTL(config.maxAllowedTTL),
		dnssec.WithLogger(config.loggerOrDefault()),
	)
	auth := &authenticator{
		ctx:    ctx,
		auth:   a,
		errors: make([]error, 0),
		queue:  make(chan authenticatorInput, 8),
	}
	go auth.start()
	return auth
}

// close shuts the queue down (once) and waits until every queued input is processed.
// It is safe to call multiple times and concurrently with addResponse.
func (a *authenticator) close() {
	a.sendMu.Lock()
	if !a.closed {
		a.closed = true
		close(a.queue)
	}
	a.sendMu.Unlock()
	a.wg.Wait()
}

func (a *authenticator) addDelegationSignerLink(z zone, qname string, udpsize uint16) {
	a.sendMu.Lock()
	if a.closed {
		a.sendMu.Unlock()
		return
	}
	a.wg.Add(1)
	a.sendMu.Unlock()

	go func() {
		defer a.wg.Done()

		go z.dnskeys(a.ctx)

		dsMsg := new(dns.Msg)
		dsMsg.SetQuestion(dns.Fqdn(qname), dns.TypeDS)
		dsMsg.SetEdns0(udpsize, true)
		dsMsg.RecursionDesired = false
		response := z.exchange(a.ctx, dsMsg)
		if !response.IsEmpty() && !response.HasError() {
			_ = a.addResponse(z, response.Msg)
		}
	}()
}

func (a *authenticator) addResponse(z zone, msg *dns.Msg) error {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	if a.closed {
		return nil
	}
	a.wg.Add(1)
	a.queue <- authenticatorInput{z, msg}
	return nil
}

func (a *authenticator) start() {
	for in := range a.queue {
		err := a.auth.AddResponse(&authZoneWrapper{ctx: a.ctx, zone: in.z}, in.msg)
		if err != nil {
			a.errMu.Lock()
			a.errors = append(a.errors, err)
			a.errMu.Unlock()
		}
		a.wg.Done()
	}
}

func (a *authenticator) result() (dnssec.AuthenticationResult, dnssec.DenialOfExistenceState, error) {
	a.close()

	a.errMu.Lock()
	errs := make([]error, len(a.errors))
	copy(errs, a.errors)
	a.errMu.Unlock()

	if len(errs) > 0 {
		if len(errs) == 1 {
			return 0, 0, errs[0]
		}
		err := errors.New("multiple errors found: ")
		for _, e := range errs {
			err = fmt.Errorf("%w: %w", err, e)
		}
	}

	return a.auth.Result()
}

func (a *authenticator) resultTTLAnswer(rtype uint16) (uint32, bool) {
	return a.auth.ResultTTLAnswer(rtype)
}

func (a *authenticator) resultTTLAuthority(rtype uint16) (uint32, bool) {
	return a.auth.ResultTTLAuthority(rtype)
}

// authZoneWrapper wraps our zone such that is supports the dnssec.Zone interface.
// Note that the dnssec package only needs querying support against this zone's nameservers.
// i.e. We do not need to try these queries recursively. If the nameservers for this zone do not return
// an authoritative answer themselves, we can assume that's an error.
type authZoneWrapper struct {
	ctx  context.Context
	zone zone
}

// Name returns the zone's apex domain name.
func (wrapper *authZoneWrapper) Name() string {
	return wrapper.zone.name()
}

// GetDNSKEYRecords Looks up the DNSKEY records for the given QName, in the zone.
func (wrapper *authZoneWrapper) GetDNSKEYRecords() ([]dns.RR, error) {
	return wrapper.zone.dnskeys(wrapper.ctx)
}
