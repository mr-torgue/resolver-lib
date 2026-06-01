package main

import (
	"context"
	"fmt"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/mr-torgue/dns"
	"github.com/mr-torgue/resolver-lib"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: dnsquery <domain> <query_type>")
		os.Exit(1)
	}

	domain := os.Args[1]
	queryType := os.Args[2]
	resolver.Query = func(s string) {
		fmt.Println("Query: " + s)
	}

	//r := resolver.NewResolver(*resolver.ConfigBuilder(resolver.WithCustomRoot("testdata/rootzones/custom.root", "testdata/rootanchors/custom-valid.xml")))
	r := resolver.NewResolver(*resolver.ConfigBuilder())

	msg := new(dns.Msg)

	var dnsType = dns.StringToType[queryType]
	//fmt.Println("Unsupported query type")
	//os.Exit(1)

	msg.SetQuestion(dns.Fqdn(domain), dnsType)
	msg.SetEdns0(4096, true)

	result := r.Exchange(context.Background(), msg)

	spew.Dump(result)
}
