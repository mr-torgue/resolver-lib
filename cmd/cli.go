package main

import (
	"context"
	"fmt"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/mr-torgue/dns"
	"github.com/mr-torgue/resolver-lib"
	"github.com/mr-torgue/resolver-lib/log"
)

type SimplepLogger struct{}

func (n SimplepLogger) Debug(args ...any)                   { fmt.Println("Query: " + fmt.Sprint(args...)) }
func (n SimplepLogger) Debugf(format string, args ...any)   { fmt.Printf("Query: "+format+"\n", args...) }
func (n SimplepLogger) Info(args ...any)                    {}
func (n SimplepLogger) Infof(format string, args ...any)    {}
func (n SimplepLogger) Warning(args ...any)                 {}
func (n SimplepLogger) Warningf(format string, args ...any) {}
func (n SimplepLogger) Error(args ...any)                   {}
func (n SimplepLogger) Errorf(format string, args ...any)   {}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: dnsquery <domain> <query_type>")
		os.Exit(1)
	}

	domain := os.Args[1]
	queryType := os.Args[2]
	var logger log.Logger = SimplepLogger{}
	resolver.SetLogger(logger)

	//r := resolver.NewResolver(*resolver.ConfigBuilder(resolver.WithCustomRoot("testdata/rootzones/custom.root", "testdata/rootanchors/custom-valid.xml")))
	r := resolver.NewResolver(resolver.ConfigBuilder(resolver.WithClient("doq", true)))

	msg := new(dns.Msg)

	var dnsType = dns.StringToType[queryType]
	//fmt.Println("Unsupported query type")
	//os.Exit(1)

	msg.SetQuestion(dns.Fqdn(domain), dnsType)
	msg.SetEdns0(4096, true)

	result := r.Exchange(context.Background(), msg)

	spew.Dump(result)
}
