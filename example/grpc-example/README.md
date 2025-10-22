# Overview
This sample is based on [gRPC Hello World](https://github.com/grpc/grpc-go/tree/master/examples).
It demonstrates how convert existing gRPC application to communicate over an app embedded zero trust 
OpenZiti Network

This example demonstrates:
* Binding a service and listening for service calls
* Dialing a service and triggering service calls

## Requirements
* an OpenZiti network. If you do not have one, you can use one of the [quickstarts](https://netfoundry.io/docs/openziti/learn/quickstarts/) to set one up.
* OpenZiti CLI to create services and identities on the OpenZiti Network

## Build the examples
Refer to the [example README](../README.md) to build the SDK examples

## Setup using the OpenZiti CLI
These steps will configure the service using the OpenZiti CLI. At the end of these steps you will have created:
* a service called `grpc`
* an identity to host (bind) the service
* an identity to connect to (dial) the service
* the service policies required to authorize the identities for bind and dial

Steps:
1. Log into OpenZiti. The host:port and username/password will vary depending on your network.

       ziti edge login localhost:1280 -u admin -p admin
1. Run this script to create everything you need.

       echo Changing to build directory
       cd $ZITI_SDK_BUILD_DIR

       echo Create the service
       ziti edge create service grpc --role-attributes grpc-service

       echo Create three identities and enroll them
       ziti edge create identity device grpc.client -a grpc.clients -o grpc.client.jwt
       ziti edge create identity device grpc.server -a grpc.servers -o grpc.server.jwt
       ziti edge enroll --jwt grpc.server.jwt
       ziti edge enroll --jwt grpc.client.jwt

       echo Create service policies
       ziti edge create service-policy grpc.dial Dial --identity-roles '#grpc.clients' --service-roles '#grpc-service'
       ziti edge create service-policy grpc.bind Bind --identity-roles '#grpc.servers' --service-roles '#grpc-service'

       echo Run policy advisor to check
       ziti edge policy-advisor services
1. Run the server.

       ./grpc-server --identity grpc.server.json --service grpc 
1. Run the client

       ./grpc-client --identity grpc.client.json --service grpc --name World
### Example output
The following is the output you'll see from the server and client side after running the previous commands.
**Server**
```
$ ./grpc-server --identity grpc.server.json --service grpc
2022/10/21 11:17:34 server listening at grpc
2022/10/21 11:18:09 Received: World
```
**Client**
```
$ ./grpc-client --identity grpc.client.json --service grpc --name World
2022/10/21 13:26:19 Greeting: Hello World
```
## Teardown
Done with the example? This script will remove everything created during setup.
```
ziti edge login localhost:1280 -u admin -p admin

echo Removing service policies
ziti edge delete service-policy grpc.dial
ziti edge delete service-policy grpc.bind

echo Removing identities
ziti edge delete identity grpc.client
ziti edge delete identity grpc.server

echo Removing service
ziti edge delete service grpc
```
