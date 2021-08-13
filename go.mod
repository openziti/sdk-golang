module github.com/openziti/sdk-golang

go 1.16

//replace github.com/openziti/foundation => ../foundation
replace github.com/openziti/sdk-golang => github.com/qrkourier/sdk-golang

require (
	github.com/Jeffail/gabs v1.4.0
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/cenkalti/backoff/v4 v4.1.1
	github.com/fullsailor/pkcs7 v0.0.0-20190404230743-d7302db945fa
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/google/uuid v1.3.0
	github.com/influxdata/influxdb1-client v0.0.0-20200827194710-b269163b24ab // indirect
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/mattn/go-isatty v0.0.13 // indirect
	github.com/michaelquigley/pfxlog v0.6.1
	github.com/mitchellh/go-ps v1.0.0
	github.com/mitchellh/mapstructure v1.4.1
	github.com/netfoundry/secretstream v0.1.2
	github.com/openziti/foundation v0.15.69
	github.com/orcaman/concurrent-map v0.0.0-20190826125027-8c72a8bb44f6
	github.com/pkg/errors v0.9.1
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475
	github.com/shirou/gopsutil v3.21.7+incompatible
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.2.1
	github.com/stretchr/testify v1.7.0
	github.com/tklauser/go-sysconf v0.3.7 // indirect
	go.mozilla.org/pkcs7 v0.0.0-20210730143726-725912489c62
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)
