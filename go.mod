module github.com/openziti/sdk-golang

go 1.16

//replace github.com/openziti/foundation => ../foundation

require (
	github.com/Jeffail/gabs v1.4.0
	github.com/StackExchange/wmi v0.0.0-20210224194228-fe8f1750fd46 // indirect
	github.com/cenkalti/backoff/v4 v4.1.1
	github.com/deepmap/oapi-codegen v1.8.2 // indirect
	github.com/fullsailor/pkcs7 v0.0.0-20190404230743-d7302db945fa
	github.com/go-ole/go-ole v1.2.5 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/google/uuid v1.3.0
	github.com/influxdata/influxdb-client-go/v2 v2.4.0
	github.com/influxdata/line-protocol v0.0.0-20210311194329-9aa0e372d097 // indirect
	github.com/michaelquigley/pfxlog v0.6.1
	github.com/mitchellh/go-ps v1.0.0
	github.com/mitchellh/mapstructure v1.4.2
	github.com/netfoundry/secretstream v0.1.2
	github.com/openziti/foundation v0.15.76
	github.com/orcaman/concurrent-map v0.0.0-20190826125027-8c72a8bb44f6
	github.com/pkg/errors v0.9.1
	github.com/rcrowley/go-metrics v0.0.0-20200313005456-10cdbea86bc0
	github.com/shirou/gopsutil v2.20.9+incompatible
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.2.1
	github.com/stretchr/testify v1.7.0
	go.mozilla.org/pkcs7 v0.0.0-20200128120323-432b2356ecb1
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1
)
