module github.com/netfoundry/ziti-sdk-golang

go 1.13

//replace github.com/netfoundry/ziti-foundation => ../ziti-foundation

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/fullsailor/pkcs7 v0.0.0-20190404230743-d7302db945fa
	github.com/google/uuid v1.1.1
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/michaelquigley/pfxlog v0.0.0-20190813191113-2be43bd0dccc
	github.com/mitchellh/mapstructure v1.1.2
	github.com/netfoundry/ziti-foundation v0.0.0-20200131162746-62af0d0834c4
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.3.0
	golang.org/x/sys v0.0.0-20191128015809-6d18c012aee9
)
