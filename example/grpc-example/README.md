# Overview
This sample is based on [gRPC Hello World](https://github.com/grpc/grpc-go/tree/master/examples).
It demonstrates how convert existing gRPC application to communicate over an app embedded zero trust 
OpenZiti Network

This example demonstrates:
* Binding a service and listening for service calls
* Dialing a service and triggering service calls

## Requirements
* go 1.19 or later
* an OpenZiti network. If you do not have one, you can use one of the [quickstarts](https://openziti.github.io/ziti/quickstarts/quickstart-overview.html) to set one up.
* OpenZiti CLI to create services and identities on the OpenZiti Network

## Build the examples
```shell
cd <repo-root-dir>/sdk-golang/example/grpc-example/
go build -o grpc-server grpc-server/main.go
go build -o grpc-client grpc-client/main.go
```

## Setup using the OpenZiti CLI
These steps will configure the service using the OpenZiti CLI. At the end of these steps you will have created:
* a service called `grpc`
* an identity to host (bind) the service
* an identity to connect to (dial) the service
* the service policies required to authorize the identities for bind and dial

Steps:
1. log into Ziti. The host:port and username/password will vary depending on your network.

       ziti edge login localhost:1280 -u admin -p admin
1. Run this script to create everything you need.

       echo Create the service
       ziti edge create service grpc --role-attributes grpc-service

       echo Create three identities and enroll them
       ziti edge create identity device grpc.client -a clients -o grpc.client.jwt
       ziti edge create identity device grpc.server -a servers -o grpc.server.jwt
       ziti edge enroll --jwt grpc.server.jwt
       ziti edge enroll --jwt grpc.client.jwt

       echo Create service policies
       ziti edge create service-policy grpc.dial Dial --identity-roles '#clients' --service-roles '#grpc-service'
       ziti edge create service-policy grpc.bind Bind --identity-roles '#servers' --service-roles '#grpc-service'

       echo Create edge router policies
       ziti edge create edge-router-policy grpc-edge-router-policy --edge-router-roles '#all' --identity-roles '#clients,#servers'
       ziti edge create service-edge-router-policy grpc-service-edge-router-policy --edge-router-roles '#all' --service-roles '#grpc-service'

       echo Run policy advisor to check
       ziti edge policy-advisor services
1. Run the server.

       ./grpc-server/server --identity grpc.server.json --service grpc 
1. Run the client

       ./grpc-client/client --identity grpc.client.json --service grpc --name World
### Example output
The following is the output you'll see from the server and client side after running the previous commands.
**Server**
```
$ ./grpc-server/server --identity grpc.server.json --service grpc
2022/10/21 11:17:34 server listening at grpc
2022/10/21 11:18:09 Received: World
```
**Client**
```
$ ./grpc-client/client --identity grpc.client.json --service grpc --name geoff
2022/10/21 13:26:19 Greeting: Hello World
```
## Teardown
Done with the example? This script will remove everything created during setup.
```
ziti edge login localhost:1280 -u admin -p admin

echo Removing edge router policies
ziti edge delete edge-router-policy grpc-edge-router-policy
ziti edge delete service-edge-router-policy grpc-service-edge-router-policy

echo Removing service policies
ziti edge delete service-policy grpc.dial
ziti edge delete service-policy grpc.bind

echo Removing identities
ziti edge delete identity grpc.client
ziti edge delete identity grpc.server

echo Removing service
ziti edge delete service grpc
```
