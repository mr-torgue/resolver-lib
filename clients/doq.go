package clients

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mr-torgue/dns"
	"github.com/quic-go/quic-go"
)

// DOQClient represents the config options for setting up a DOQ based client.
type DOQClient struct {
	Port      string
	TLSConfig *tls.Config
	Timeout   time.Duration
}

// ExchangeContext sends msg to the address specified in addr (without port number).
func (c *DOQClient) ExchangeContext(ctx context.Context, msg *dns.Msg, addr string) (rsp *dns.Msg, rtt time.Duration, err error) {

	addr = net.JoinHostPort(addr, c.Port)
	// use a smaller timeout
	readCtx, cancelConnect := context.WithTimeout(ctx, c.Timeout)
	defer cancelConnect()
	session, err := quic.DialAddr(readCtx, addr, c.TLSConfig, nil)
	// NOTE: is there a simpler way to detect if a server supports QUIC instead of relying on timeouts?
	if err != nil {
		return nil, 0, err
	}
	defer session.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
	// ref: https://www.rfc-editor.org/rfc/rfc9250.html#name-dns-message-ids
	msg.Id = 0

	// get the DNS Message in wire format.
	b, err := msg.Pack()
	if err != nil {
		return nil, 0, err
	}

	t := time.Now()
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return nil, 0, err
	}

	msgLen := uint16(len(b))
	msgLenBytes := []byte{byte(msgLen >> 8), byte(msgLen & 0xFF)}
	if _, err = stream.Write(msgLenBytes); err != nil {
		return nil, 0, err
	}
	// Make a QUIC request to the DNS server with the DNS message as wire format bytes in the body.
	if _, err = stream.Write(b); err != nil {
		return nil, 0, err
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will be
	// sent on that stream. Note, that stream.Close() closes the write-direction
	// of the stream, but does not prevent reading from it.
	// See: https://github.com/AdguardTeam/dnsproxy/blob/f901a5f4b9e8d5f143dce459067bc6614c6d927d/upstream/doq.go#L247-L254
	err = stream.Close()
	if err != nil {
		return nil, 0, fmt.Errorf("unable to close quic stream: %w", err)
	}

	// Use a separate context with timeout for reading the response
	readCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	var buf []byte
	errChan := make(chan error, 1)
	go func() {
		var err error
		buf, err = io.ReadAll(stream)
		errChan <- err
	}()

	select {
	case err := <-errChan:
		if err != nil {
			return nil, 0, err
		}
	case <-readCtx.Done():
		return nil, 0, fmt.Errorf("timeout reading response")
	}

	rtt = time.Since(t)

	if len(buf) < 2 {
		return nil, rtt, fmt.Errorf("response too short: got %d bytes, need at least 2", len(buf))
	}

	packetLen := binary.BigEndian.Uint16(buf[:2])
	if packetLen != uint16(len(buf[2:])) {
		return nil, rtt, fmt.Errorf("packet length mismatch")
	}
	// prepare the result
	rsp = new(dns.Msg)
	if err = rsp.Unpack(buf[2:]); err != nil {
		return nil, rtt, err
	}

	return rsp, rtt, nil
}
