package resolver

import (
	"context"
	"errors"
	"fmt"
	"syscall"

	"github.com/miekg/dns"
)

func (pool *nameserverPool) exchange(ctx context.Context, m *dns.Msg) *Response {
	hasIPv4 := pool.hasIPv4()
	hasIPv6 := pool.hasIPv6()

	if !hasIPv4 && !hasIPv6 {
		if z, ok := ctx.Value(ctxZoneName).(string); ok {
			return newResponseError(fmt.Errorf("%w [%s]", ErrNoPoolConfiguredForZone, z))
		}
		return newResponseError(ErrNoPoolConfiguredForZone)
	}

	//---

	var response *Response

	if hasIPv6 && IPv6Available() {
		if server := pool.getIPv6(); server != nil {
			response = server.exchange(ctx, m)
			if response.HasError() && errors.Is(response.Err, syscall.ENETUNREACH) {
				// No IPv6 route (anymore): latch IPv6 off for the rest of the
				// process so later queries go straight to IPv4.
				markIPv6Unavailable()
			}
		}
	} else {
		if server := pool.getIPv4(); server != nil {
			response = server.exchange(ctx, m)
		}
	}

	// removed  || response.truncated()  because it gave issues.
	// Not sure if this is correct.
	if response.IsEmpty() || response.HasError() {
		// If there was an issue, we give it one more try.
		// If we have more than one nameserver, this will try a different one.
		if hasIPv4 {
			if server := pool.getIPv4(); server != nil {
				response = server.exchange(ctx, m)
			}
		} else {
			if server := pool.getIPv6(); server != nil {
				response = server.exchange(ctx, m)
			}
		}
	}

	if response.IsEmpty() || response.HasError() {
		errMsg := fmt.Sprintf("all nameservers tried returned an unsucessful response for qname [%s]", m.Question[0].Name)
		if z, ok := ctx.Value(ctxZoneName).(string); ok {
			errMsg = errMsg + fmt.Sprintf(" in zone [%s]", z)
		}

		err := fmt.Errorf("%w: %s", ErrUnableToResolveAnswer, errMsg)

		if response.HasError() {
			// If we already had an error, we'll wrap it with this one.
			response.Err = fmt.Errorf("%w: %w", response.Err, err)
		} else {
			response.Err = err
		}
	}

	return response
}
