module github.com/openziti/sdk-golang

go 1.15

//replace github.com/openziti/foundation => ../foundation

require (
	github.com/Jeffail/gabs v1.4.0
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/cenkalti/backoff/v4 v4.1.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/fullsailor/pkcs7 v0.0.0-20190404230743-d7302db945fa
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/google/uuid v1.2.0
	github.com/michaelquigley/pfxlog v0.3.7
	github.com/mitchellh/go-ps v1.0.0
	github.com/mitchellh/mapstructure v1.4.1
	github.com/netfoundry/secretstream v0.1.2
	github.com/openziti/foundation v0.15.18
	github.com/orcaman/concurrent-map v0.0.0-20190826125027-8c72a8bb44f6
	github.com/pkg/errors v0.9.1
	github.com/rcrowley/go-metrics v0.0.0-20200313005456-10cdbea86bc0
	github.com/shirou/gopsutil v2.20.9+incompatible
	github.com/sirupsen/logrus v1.7.1
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.7.0
	go.mozilla.org/pkcs7 v0.0.0-20200128120323-432b2356ecb1
	golang.org/x/sys v0.0.0-20200625212154-ddb9806d33ae
)
