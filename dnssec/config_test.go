package dnssec_test

import (
	"testing"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver/dnssec"
	"github.com/stretchr/testify/assert"
)

func TestLoadAnchors(t *testing.T) {

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		anchorfile     string
		expectedAnswer []*dns.DS
	}{
		{
			name:       "standard root-anchors",
			anchorfile: "../testdata/rootanchors/root-anchors.xml",
			expectedAnswer: []*dns.DS{
				test.DS(".	86400	IN	DS	20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
				test.DS(".	86400	IN	DS	38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
			},
		},
		{
			name:       "custom root-anchors",
			anchorfile: "../testdata/rootanchors/custom-valid.xml",
			expectedAnswer: []*dns.DS{
				test.DS(".	86400	IN	DS	20537 15 2 1D551A7E4DA7AC1EB4311D44FEF74981213DEFA8E85CAED00ABB53BF"),
				test.DS(".  86400   IN  DS  50759  8 2 0D1B5D1A7125BD5DF626FD6563ABC4B2C40905D06E62DE7D99EBFB08"),
			},
		},
		//{"invalid root-anchors", "testdata/rootanchors/root-anchors.xml"},
		//{"custom root-anchors", "testdata/rootanchors/root-anchors.xml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnssec.LoadAnchors(tt.anchorfile)
			assert.Equal(t, len(tt.expectedAnswer), len(dnssec.RootTrustAnchors), "lengths of DS records should be equal")
			for i := range tt.expectedAnswer {
				assert.Equal(t, tt.expectedAnswer[i].Digest, dnssec.RootTrustAnchors[i].Digest, "Digest should match")
				assert.Equal(t, tt.expectedAnswer[i].Hdr.Rrtype, dnssec.RootTrustAnchors[i].Hdr.Rrtype, "RR types should match")
				assert.Equal(t, tt.expectedAnswer[i].Algorithm, dnssec.RootTrustAnchors[i].Algorithm, "Algorithm should match")
				assert.Equal(t, tt.expectedAnswer[i].DigestType, dnssec.RootTrustAnchors[i].DigestType, "DigestType should match")
				assert.Equal(t, tt.expectedAnswer[i].KeyTag, dnssec.RootTrustAnchors[i].KeyTag, "KeyTag should match")
				assert.Equal(t, tt.expectedAnswer[i].Hdr.Ttl, dnssec.RootTrustAnchors[i].Hdr.Ttl, "TTL should match")

			}
		})
	}
	assert.NotNil(t, dnssec.RootTrustAnchors, "RootTrustAnchors should not be nil")
}
