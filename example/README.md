# OpenZiti Go SDK Examples

This folder contains examples showing how to use the OpenZiti Go SDK

## Building the SDK Examples

### Requirements
* go 1.19 or later
* gcc compiler

### Build
Execute the following to build all examples. They will be placed in a folder in the example directory labeled `build`
1. CD to the example directory

       cd <repo-repo-dir>/example
1. Run the following to create the build directory and build the examples

       export ZITI_SDK_BUILD_DIR=$(pwd)/build
       mkdir $ZITI_SDK_BUILD_DIR
       go mod tidy
       go build -o build ./...

## SDK Examples Overview
### [chat](./chat)

This demonstrates how to build network applications using the SDK with
a CLI based chat server and client.

### [chat-p2p](./chat-p2p)

This demonstrates how to build P2P network applications with a CLI based
chat application which is modeled loosely on a VoIP.

### [curlz](./curlz)

Shows how to integrate the SDK with the Go net/http library as a client.

### [simple-server](./simple-server)

Shows how to integrate the SDK with the Go net/http library as a server.

### [grpc-example](./grpc-example)

Shows how to integrate the SDK with GRPC as a client and server.

### [influxdb-client-go](./influxdb-client-go)

Shows how to have the influxdb client work using the SDK.

### [reflect](./reflect)

Basic echo client and server built with the SDK.

### [zcat](./zcat)

Netcat like application which can work over OpenZiti.

### [zping](./zping)

Client and server applications for measuring latency over an OpenZiti network.