package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/mr-torgue/dns"
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
}

func (n *nameserver) defaultDnsClientFactory(protocol string) dnsClient {
	if protocol == "doq" {
		// set up client
		if n.quicClient == nil {
			tlsconf := &tls.Config{
				NextProtos:         []string{"doq"},
				ServerName:         dns.Fqdn(n.hostname),
				InsecureSkipVerify: GlobalConfig.insecureSkipVerify,
			}
			n.quicClient = &clients.DOQClient{TLSConfig: tlsconf, Port: "853", Timeout: GlobalConfig.doqTimeout}
		}
		return n.quicClient
	} else if protocol == "dot" {
		if n.tlsClient == nil {
			tlsconf := &tls.Config{
				ServerName:         dns.Fqdn(n.hostname),
				InsecureSkipVerify: GlobalConfig.insecureSkipVerify,
			}
			n.tlsClient = &clients.ClassicClient{Port: "853", Client: &dns.Client{
				Net:       "tcp-tls",
				Timeout:   GlobalConfig.dotTimeout,
				TLSConfig: tlsconf,
			}}
		}
		return n.tlsClient
	}
	// defaults to UDP
	timeout := GlobalConfig.udpTimeout
	if protocol == "tcp" {
		timeout = GlobalConfig.tcpTimeout
	}
	return &clients.ClassicClient{Port: "53", Client: &dns.Client{Net: protocol, Timeout: timeout}}
}

// newNameserver creates a new nameserver and sets the correct dnsClientFactory.
// Note: there are probably cleaner ways of doing this.
func newNameserver(hostname, addr string) *nameserver {
	ns := nameserver{
		hostname: hostname,
		addr:     addr,
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
	for _, protocol := range GlobalConfig.protocols {
		client := factory(protocol)

		r.Msg, r.Duration, r.Err = client.ExchangeContext(ctx, m, nameserver.addr)

		//---

		shortId := "unknown"
		iteration := uint32(0)
		if trace, _ := ctx.Value(CtxTrace).(*Trace); trace != nil {
			shortId = trace.ShortID()
			iteration = trace.Iteration()
		}
		Query(fmt.Sprintf(
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
		))

		go nameserver.updateMetrics(protocol, r.Duration)

		// If we got an error back, we'll continue to maybe try again.
		if r.HasError() {
			continue
		}

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
