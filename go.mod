module github.com/mr-torgue/resolver-lib

go 1.27.4

require (
	github.com/coredns/coredns v1.15.0
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
	github.com/google/uuid v1.6.0
	github.com/miekg/dns v1.1.73
	github.com/quic-go/quic-go v0.64.1
	github.com/stretchr/testify v1.12.1
)

require (
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/miekg/dns => github.com/mr-torgue/dns v1.2.0
