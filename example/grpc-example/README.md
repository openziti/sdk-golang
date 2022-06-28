# GRPC sample

## Introduction

This sample is based on [gRPC Hello World](https://github.com/grpc/grpc-go/tree/master/examples).
It demonstrates how convert existing gRPC application to communicate over a Ziti Network

## Instructions

### Build the code

```console
$ go get github.com/openziti/sdk-golang/example/grpc-example/grpc-client
$ go get github.com/openziti/sdk-golang/example/grpc-example/grpc-server
```

### Create Ziti identities and Service

Follow instructions to create the following:

- [identity](https://openziti.github.io/ziti/identities/overview.html)
- [service](https://openziti.github.io/ziti/services/overview.html)
- [policies](https://openziti.github.io/ziti/policies/overview.html)

or use [Ziti Edge Developer Sandbox](https://zeds.openziti.org) for simplified provisioning.

### Run!

Start server

```console
$ $(go env GOPATH)/bin/grpc_server <server_identity> <service_nme> &
```

Run client

```console
$ $(go env GOPATH)/bin/grpc_client <client_identity> <service_nme> 
```