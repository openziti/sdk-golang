# Overview
This example is a basic chat client showing how to embed zero trust connectivity into both server-side and client-side 
code. The server handles chat messages and broadcasts them to other clients on the chat.

This example demonstrates:
* Binding a service and listening for message events
* Dialing a service and triggering message events

# Requirements
* go 1.19 or later
* an OpenZiti network. If you do not have one, you can use one of the [quickstarts](https://openziti.github.io/ziti/quickstarts/quickstart-overview.html) to set one up.
* OpenZiti CLI to create services and identities on the OpenZiti Network

# Build the examples
```shell
cd <repo-root-dir>/sdk-golang/example/chat/
go build -o chat-server chat-server/chat-server.go
go build -o chat-client chat-client/chat-client.go
```

# Setup using the OpenZiti CLI
These steps will configure the service using the OpenZiti CLI. At the end of these steps you will have created:
* a service called `chat`
* an identity to host (bind) the service
* two identities to connect to (dial) the service
* the service policies required to authorize the identities for bind and dial

Steps:
1. log into Ziti. The host:port and username/password will vary depending on your network.

       ziti edge login localhost:1280 -u admin -p admin
1. Run this script to create everything you need.

       echo Create the service
       ziti edge create service chat --role-attributes chat-service
       
       echo Create three identities and enroll them
       ziti edge create identity user chevy -a clients -o chevy.jwt
       ziti edge create identity user dan -a clients -o dan.jwt
       ziti edge create identity device chat.server -a servers -o chat.server.jwt
       ziti edge enroll --jwt chat.server.jwt
       ziti edge enroll --jwt chevy.jwt
       ziti edge enroll --jwt dan.jwt
       
       echo Create service policies
       ziti edge create service-policy chat.dial Dial --identity-roles '#clients' --service-roles '#chat-service'
       ziti edge create service-policy chat.bind Bind --identity-roles '#servers' --service-roles '#chat-service'
       
       echo Create edge router policies
       ziti edge create edge-router-policy chat-edge-router-policy --edge-router-roles '#all' --identity-roles '#clients,#servers'
       ziti edge create service-edge-router-policy chat-service-edge-router-policy --edge-router-roles '#all' --service-roles '#chat-service'
       
       echo Run policy advisor to check
       ziti edge policy-advisor services
1. Run the server.

       ./chat-server/chat-server chat.server.json 
1. Run a client

       ./chat-client/chat-client chevy chevy.json
1. Run another client

       ./chat-client/chat-client dan dan.json
## Example output
The following is the output you'll see from the server and client side after running the previous commands.
**Server**
```
$ ./chat-server/chat-server chat.server.json
INFO[0000] binding service chat
INFO[0014] new connection
INFO[0014] client 'chevy' connected
INFO[0038] new connection
INFO[0038] client 'dan' connected
```
**Client 1 (Chevy)**
```
$ ./chat-client/chat-client chevy chevy.json
doctor
dan: doctor
```
**Client 2 (Dan)**
```
$ ./chat-client/chat-client dan dan.json
chevy: doctor
doctor
```
# Teardown
Done with the example? This script will remove everything created during setup.
```
ziti edge login localhost:1280 -u admin -p admin

echo Removing edge router policies
ziti edge delete edge-router-policy chat-edge-router-policy
ziti edge delete service-edge-router-policy chat-service-edge-router-policy

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
