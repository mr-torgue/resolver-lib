package dnssec

import (
	"io"
	"strings"
	"time"

	"github.com/mr-torgue/dns"
	"github.com/mr-torgue/go-openssl"
)

const DnskeyFlagCsk = 257
const zoneName = "example.com."

//---

type mockZone struct {
	name string
	set  []dns.RR
	err  error
}

func (t *mockZone) Name() string {
	return t.name
}

func (t *mockZone) GetDNSKEYRecords() ([]dns.RR, error) {
	return t.set, t.err
}

//---

func newRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

type testKey struct {
	key    *dns.DNSKEY
	ds     *dns.DS
	signer openssl.PrivateKey
}

func testRsaKey() *testKey {
	dnskey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   zoneName,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Flags:     DnskeyFlagCsk,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	secret, err := dnskey.Generate(2048)
	if err != nil {
		panic(err)
	}
	return &testKey{
		ds:     dnskey.ToDS(dns.SHA256),
		key:    dnskey,
		signer: secret,
	}
}

func testEcKey() *testKey {
	dnskey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   zoneName,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Flags:     DnskeyFlagCsk,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	secret, err := dnskey.Generate(256)
	if err != nil {
		panic(err)
	}
	return &testKey{
		ds:     dnskey.ToDS(dns.SHA256),
		key:    dnskey,
		signer: secret,
	}
}

func testED25519KeyFromReader(publicReader, secretReader io.Reader) *testKey {
	public, err := io.ReadAll(publicReader)
	if err != nil {
		panic(err)
	}

	dnskey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   zoneName,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Flags:     DnskeyFlagCsk,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: strings.TrimSpace(string(public)),
	}

	secret, err := dnskey.ReadPrivateKey(secretReader, "local io.Reader")
	if err != nil {
		panic(err)
	}
	return &testKey{
		ds:     dnskey.ToDS(dns.SHA256),
		key:    dnskey,
		signer: secret,
	}
}

func (k *testKey) sign(rrset []dns.RR, inception, expiration int64) *dns.RRSIG {
	if inception == 0 {
		inception = time.Now().Add(time.Hour * -24).Unix()
	}
	if expiration == 0 {
		expiration = time.Now().Add(time.Hour * 24).Unix()
	}
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{},
		Inception:  uint32(inception),
		Expiration: uint32(expiration),
		KeyTag:     k.key.KeyTag(),
		SignerName: k.key.Header().Name,
		Algorithm:  k.key.Algorithm,
	}
	err := rrsig.Sign(k.signer, rrset)
	if err != nil {
		panic(err)
	}
	return rrsig
}
