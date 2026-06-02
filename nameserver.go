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

func (*nameserver) defaultDnsClientFactory(protocol string) dnsClient {
	timeout := config.udpTimeout
	if protocol == "tcp" {
		timeout = config.tcpTimeout
	}
	return &clients.ClassicClient{Port: "53", Client: &dns.Client{Net: protocol, Timeout: timeout}}
}

// doqClientFactory build the factory for a doq client.
func (n *nameserver) doqClientFactory(protocol string) dnsClient {
	if protocol == "doq" {
		// set up client
		if n.quicClient == nil {
			tlsconf := &tls.Config{
				NextProtos:         []string{"doq"},
				ServerName:         dns.Fqdn(n.hostname),
				InsecureSkipVerify: config.insecureSkipVerify,
			}
			n.quicClient = &clients.DOQClient{TLSConfig: tlsconf, Port: "853", Timeout: config.doqTimeout}
		}
		return n.quicClient
	}
	return n.defaultDnsClientFactory(protocol)
}

func (n *nameserver) dotClientFactory(protocol string) dnsClient {
	if protocol == "dot" {
		return &clients.ClassicClient{Port: "853", Client: &dns.Client{
			Net:     "tcp-tls",
			Timeout: config.dotTimeout,
			TLSConfig: &tls.Config{
				ServerName:         dns.Fqdn(n.hostname),
				InsecureSkipVerify: config.insecureSkipVerify,
			},
		}}
	}
	return n.defaultDnsClientFactory(protocol)
}

// setDnsClientFactory sets ns.dnsClientFactory
// based on the client option given in config.client.
func (ns *nameserver) setDnsClientFactory(client string) {
	switch client {
	case "udp":
		ns.dnsClientFactory = ns.defaultDnsClientFactory
	case "tcp":
		ns.dnsClientFactory = ns.defaultDnsClientFactory
	case "dot":
		ns.dnsClientFactory = ns.dotClientFactory
	case "doq":
		ns.dnsClientFactory = ns.doqClientFactory
	default:
		panic("Only the following clients are supported: udp, tcp, dot, and doq")
	}
}

// newNameserver creates a new nameserver and sets the correct dnsClientFactory.
// Note: there are probably cleaner ways of doing this.
func newNameserver(hostname, addr, client string) *nameserver {
	ns := nameserver{
		hostname: hostname,
		addr:     addr,
	}
	ns.setDnsClientFactory(client)
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
	for _, protocol := range config.protocols {
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
