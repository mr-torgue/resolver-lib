package clients

import (
	"context"
	"net"
	"time"

	"github.com/mr-torgue/dns"
)

// Wrapper around dns.Client. It takes care of Name Servers running on different ports.

type ClassicClient struct {
	Port   string
	Client *dns.Client
}

func (client *ClassicClient) ExchangeContext(ctx context.Context, msg *dns.Msg, ip string) (*dns.Msg, time.Duration, error) {
	addr := net.JoinHostPort(ip, client.Port)
	return client.Client.ExchangeContext(ctx, msg, addr)
}
