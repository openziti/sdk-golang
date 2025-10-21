# Overview
This example is a basic chat client showing how to embed zero trust connectivity into both server-side and client-side 
code. The server handles chat messages and broadcasts them to other clients on the chat.

This example demonstrates:
* Binding a service and listening for message events
* Dialing a service and triggering message events

# Requirements
* an OpenZiti network. If you do not have one, you can use one of the [quickstarts](https://netfoundry.io/docs/openziti/learn/quickstarts/) to set one up.
* OpenZiti CLI to create services and identities on the OpenZiti Network

## Build the examples
Refer to the [example README](../README.md) to build the SDK examples

# Setup using the OpenZiti CLI
These steps will configure the service using the OpenZiti CLI. At the end of these steps you will have created:
* a service called `chat`
* an identity to host (bind) the service
* two identities to connect to (dial) the service
* the service policies required to authorize the identities for bind and dial

Steps:
1. Log into OpenZiti. The host:port and username/password will vary depending on your network.

       ziti edge login localhost:1280 -u admin -p admin
1. Run this script to create everything you need.

       echo Changing to build directory
       cd $ZITI_SDK_BUILD_DIR
       
       echo Create the service
       ziti edge create service chat --role-attributes chat-service
       
       echo Create three identities and enroll them
       ziti edge create identity user chevy -a chat.clients -o chevy.jwt
       ziti edge create identity user dan -a chat.clients -o dan.jwt
       ziti edge create identity device chat.server -a chat.servers -o chat.server.jwt
       ziti edge enroll --jwt chat.server.jwt
       ziti edge enroll --jwt chevy.jwt
       ziti edge enroll --jwt dan.jwt
       
       echo Create service policies
       ziti edge create service-policy chat.dial Dial --identity-roles '#chat.clients' --service-roles '#chat-service'
       ziti edge create service-policy chat.bind Bind --identity-roles '#chat.servers' --service-roles '#chat-service'
       
       echo Run policy advisor to check
       ziti edge policy-advisor services
1. Run the server.

       ./chat-server chat.server.json 
1. Run a client

       ./chat-client chevy chevy.json
1. Run another client

       ./chat-client dan dan.json
## Example output
The following is the output you will see from the server and client side after running the previous commands.
**Server**
```
$ ./chat-server chat.server.json
INFO[0000] binding service chat
INFO[0014] new connection
INFO[0014] client 'chevy' connected
INFO[0038] new connection
INFO[0038] client 'dan' connected
```
**Client 1 (Chevy)**
```
$ ./chat-client chevy chevy.json
doctor
dan: doctor
```
**Client 2 (Dan)**
```
$ ./chat-client dan dan.json
chevy: doctor
doctor
```
# Teardown
Done with the example? This script will remove everything created during setup.
```
ziti edge login localhost:1280 -u admin -p admin

echo Removing service policies
ziti edge delete service-policy chat.dial
ziti edge delete service-policy chat.bind

echo Removing identities
ziti edge delete identity chevy
ziti edge delete identity dan
ziti edge delete identity chat.server

echo Removing service
ziti edge delete service chat
```
