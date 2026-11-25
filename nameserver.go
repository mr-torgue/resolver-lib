package resolver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/mr-torgue/resolver-lib/clients"
)

// dnsClientFactory defines a factory function for creating a DNS client.
type dnsClientFactory func(string) dnsClient

type dnsClient interface {
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type nameserver struct {
	hostname string
	addr     string

	dnsClientFactory dnsClientFactory
	// store for reuse
	quicClient *clients.DOQClient
	tlsClient  *clients.ClassicClient

	metricsLock         sync.Mutex
	numberOfRequests    uint32
	totalResponseTime   time.Duration
	averageResponseTime time.Duration
	numberOfTcpRequests uint32
	protocolRatio       float32

	// negative cache: set when a DoQ/DoT setup against this address fails.
	// the blacklisting expires after protoBlacklistInterval, so a nameserver
	// that starts (or stops) offering the protocol is eventually retried.
	doqFailedUntil atomic.Int64 // unix nanoseconds until which DoQ is skipped
	dotFailedUntil atomic.Int64 // unix nanoseconds until which DoT is skipped
	config         *Config      // make sure that this config points to the same as resolver
}

// protoBlacklistInterval is how long a protocol blacklisted for this
// nameserver stays blacklisted. Errors like 'no DoT on this address' are
// sticky, but servers can change, so we retry the protocol once a day.
const protoBlacklistInterval = 24 * time.Hour

// protoSkipped reports whether a protocol should be skipped for this nameserver.
// udp/tcp are never skipped (they're cheap to try).
func (n *nameserver) protoSkipped(protocol string) bool {
	switch protocol {
	case "doq":
		return time.Now().UnixNano() < n.doqFailedUntil.Load()
	case "dot":
		return time.Now().UnixNano() < n.dotFailedUntil.Load()
	}
	return false
}

func (n *nameserver) markProto(protocol string, failed bool) {
	var failedUntil *atomic.Int64
	switch protocol {
	case "doq":
		failedUntil = &n.doqFailedUntil
	case "dot":
		failedUntil = &n.dotFailedUntil
	default:
		return
	}
	if failed {
		failedUntil.Store(time.Now().Add(protoBlacklistInterval).UnixNano())
	} else {
		failedUntil.Store(0) // success: clear the blacklist
	}
}

// protoSetupError reports whether an exchange error indicates that the address
// does not offer the protocol at all (e.g. the DoQ/DoT session could not be
// established), rather than a transient, query-level failure such as a
// server-side stream reset or a read timeout. Only setup errors may blacklist
// the protocol for this server: a transient error must not disable it
// permanently, otherwise a single hiccup takes the protocol out for the
// lifetime of the nameserver and every following query fails immediately.
func protoSetupError(protocol string, err error) bool {
	switch protocol {
	case "doq":
		// A DoQ error is only a setup error if the QUIC session could not be
		// established (server does not speak DoQ/QUIC on this address).
		// Once a session existed, the error (stream reset, read timeout)
		// came from the server and may be transient.
		return errors.Is(err, clients.ErrNoDoQ)
	case "dot":
		// A DoT error is only a setup error if the TCP connection could not
		// be established. Once connected, the failure may be transient.
		var opErr *net.OpError
		return errors.As(err, &opErr) && opErr.Op == "dial"
	}
	return false
}

// Todo: use same tlsconfig for doq and dot to reuse code.
func (n *nameserver) defaultDnsClientFactory(protocol string) dnsClient {
	if protocol == "doq" {
		// set up client
		if n.quicClient == nil {
			tlsconf := &tls.Config{
				NextProtos:         []string{"doq"},
				ServerName:         dns.Fqdn(n.hostname),
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: n.config.insecureSkipVerify,
				ClientSessionCache: n.config.tlsCache,
			}
			if n.config.pqcMode {
				tlsconf.CurvePreferences = []tls.CurveID{
					tls.X25519MLKEM768,
					tls.SecP256r1MLKEM768,
				}
			} else {
				tlsconf.CurvePreferences = []tls.CurveID{
					tls.X25519MLKEM768,
					tls.SecP256r1MLKEM768,
					tls.X25519,
					tls.CurveP256,
				}
			}
			n.quicClient = &clients.DOQClient{TLSConfig: tlsconf, Port: n.config.doqPort, Timeout: n.config.doqTimeout}
		}
		return n.quicClient
	} else if protocol == "dot" {
		if n.tlsClient == nil {
			tlsconf := &tls.Config{
				ServerName:             dns.Fqdn(n.hostname),
				MinVersion:             tls.VersionTLS13,
				InsecureSkipVerify:     n.config.insecureSkipVerify,
				ClientSessionCache:     n.config.tlsCache,
				SessionTicketsDisabled: false,
			}
			if n.config.pqcMode {
				tlsconf.CurvePreferences = []tls.CurveID{
					tls.X25519MLKEM768,
					tls.SecP256r1MLKEM768,
				}
			} else {
				tlsconf.CurvePreferences = []tls.CurveID{
					tls.X25519MLKEM768,
					tls.SecP256r1MLKEM768,
					tls.X25519,
					tls.CurveP256,
				}
			}
			n.tlsClient = &clients.ClassicClient{Port: n.config.dotPort, Client: &dns.Client{
				Net:       "tcp-tls",
				Timeout:   n.config.dotTimeout,
				TLSConfig: tlsconf,
			}}
		}
		return n.tlsClient
	}
	// defaults to UDP
	timeout := n.config.udpTimeout
	if protocol == "tcp" {
		timeout = n.config.tcpTimeout
	}
	return &clients.ClassicClient{Port: n.config.dnsPort, Client: &dns.Client{Net: protocol, Timeout: timeout}}
}

// newNameserver creates a new nameserver and sets the correct dnsClientFactory.
// Note: there are probably cleaner ways of doing this.
func newNameserver(hostname, addr string, config *Config) *nameserver {
	ns := nameserver{
		hostname: hostname,
		addr:     addr,
		config:   config,
	}
	return &ns
}

func (nameserver *nameserver) exchange(ctx context.Context, m *dns.Msg) *Response {
	factory := nameserver.defaultDnsClientFactory
	if nameserver.dnsClientFactory != nil {
		factory = nameserver.dnsClientFactory
	}

	zoneName := "unknown"
	if z, ok := ctx.Value(ctxZoneName).(string); ok {
		zoneName = z
	}

	if m == nil {
		return newResponseError(fmt.Errorf("%w in zone [%s]", ErrNilMessageSentToExchange, zoneName))
	}

	r := Response{}
	for _, protocol := range nameserver.config.protocols {
		if nameserver.protoSkipped(protocol) {
			continue // e.g. this server has no DoQ: don't pay the dial timeout again
		}

		client := factory(protocol)

		r.Msg, r.Duration, r.Err = client.ExchangeContext(ctx, m, nameserver.addr)

		//---

		shortId := "unknown"
		iteration := uint32(0)
		if trace, _ := ctx.Value(CtxTrace).(*Trace); trace != nil {
			shortId = trace.ShortID()
			iteration = trace.Iteration()
		}
		// debug query
		Log.Debugf(
			"%s-%d: %s taken querying [%s] %s in zone [%s] on %s://%s (%s)",
			shortId,
			iteration,
			r.Duration,
			m.Question[0].Name,
			TypeToString(m.Question[0].Qtype),
			zoneName,
			protocol,
			nameserver.hostname,
			nameserver.addr,
		)

		go nameserver.updateMetrics(protocol, r.Duration)

		// If we got an error back, we'll continue to maybe try again.
		if r.HasError() {
			if protoSetupError(protocol, r.Err) {
				// The address does not offer this protocol: blacklist it for this server.
				nameserver.markProto(protocol, true)
			}
			continue
		}
		nameserver.markProto(protocol, false) // success: clear the flag

		// Then we can return straight away.
		if !r.Msg.Truncated {
			return &r
		}
	}

	// r here may have an error. It might be truncated. But it's the best we've got.
	return &r
}

func (nameserver *nameserver) updateMetrics(protocol string, duration time.Duration) {
	nameserver.metricsLock.Lock()

	nameserver.numberOfRequests++

	nameserver.totalResponseTime = nameserver.totalResponseTime + duration
	nameserver.averageResponseTime = nameserver.totalResponseTime / time.Duration(nameserver.numberOfRequests)

	if protocol == "tcp" {
		nameserver.numberOfTcpRequests++
	}

	nameserver.protocolRatio = float32(nameserver.numberOfTcpRequests) / float32(nameserver.numberOfRequests)

	nameserver.metricsLock.Unlock()
}
