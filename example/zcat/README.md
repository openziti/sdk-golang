# Overview
This example illustrates how to embed zero trust connectivity into a Netcat like application.

This example demonstrates:
* Dialing a service

## Requirements
* an OpenZiti network. If you do not have one, you can use one of the [quickstarts](https://openziti.github.io/ziti/quickstarts/quickstart-overview.html) to set one up.
* OpenZiti CLI to create services and identities on the OpenZiti Network

## Build the example
Refer to the [example README](../README.md) to build the SDK examples

## Setup using the OpenZiti CLI
These steps will configure the service using the OpenZiti CLI. At the end of these steps you will have created:
* a service called `zcat`
* an identity to connect to (dial) the service
* the service config to connect the service to the overlay
* the service policies required to authorize the identities for bind and dial

Steps:
1. log into Ziti. The host:port and username/password will vary depending on your network.

       ziti edge login localhost:1280 -u admin -p admin
1. Run this script to create everything you need.

       cd <repo-root-dir>/example/build

       echo Create the service configs
       ziti edge create config zcat.hostv1 host.v1 '{"protocol":"tcp", "address":"localhost","port":'8080'}'
       ziti edge create config zcat.interceptv1 intercept.v1 '{"protocols":["tcp"],"addresses":["zcat.ziti"], "portRanges":[{"low":'8080', "high":'8080'}]}'

       echo Create the service
       ziti edge create service zcat --configs "zcat.hostv1,zcat.interceptv1" --role-attributes zcat-service
       
       echo Create two identities and enroll the server
       ziti edge create identity device zcat-client -a clients -o zcat-client.jwt
       ziti edge create identity device zcat-server -a servers -o zcat-server.jwt
       ziti edge enroll --jwt zcat-server.jwt
       ziti edge enroll --jwt zcat-client.jwt
       
       echo Create service policies
       ziti edge create service-policy zcat.dial Dial --identity-roles '#clients' --service-roles '#zcat-service'
       ziti edge create service-policy zcat.bind Bind --identity-roles '#servers' --service-roles '#zcat-service'
       
       echo Create edge router policies
       ziti edge create edge-router-policy zcat-edge-router-policy --edge-router-roles '#all' --identity-roles '#clients,#servers'
       ziti edge create service-edge-router-policy zcat-service-edge-router-policy --edge-router-roles '#all' --service-roles '#zcat-service'
       
       echo Run policy advisor to check
       ziti edge policy-advisor services
1. Run the server.

       ./simple-server simple-server.json simpleService

1. Enroll the client identity
   1. Refer to [enrolling documentation](https://openziti.github.io/ziti/identities/enrolling.html) for details

1. Issue cURL commands to see the server side responses in action
   1. curl http://localhost:8080?name=client
   2. curl http://simpleService.ziti:8080?name=client

### Example output
The following is the output you'll see from the server and client side after running the previous commands.
**Server**
```
$ ./simple-server simple-server.json simpleService
listening for non-ziti requests on localhost:8080
listening for requests for Ziti service simpleService
Saying hello to client, coming in from plain-internet
Saying hello to client, coming in from ziti
```
**Client**
```
$ curl http://localhost:8080\?name\=client
Hello, client, from plain-internet

$ curl http://simpleService.ziti:8080?name=client
Hello, client, from ziti
```

## Teardown
Done with the example? This script will remove everything created during setup.
You will have to manually remove the identity from your Ziti Desktop Edge application.
```
ziti edge login localhost:1280 -u admin -p admin

echo Removing edge router policies
ziti edge delete edge-router-policy zcat-edge-router-policy
ziti edge delete service-edge-router-policy zcat-service-edge-router-policy

echo Removing service policies
ziti edge delete service-policy zcat.dial
ziti edge delete service-policy zcat.bind

echo Removing service configs
ziti edge delete config zcat.hostv1
ziti edge delete config zcat.interceptv1

echo Removing identities
ziti edge delete identity zcat-client
ziti edge delete identity zcat-server

echo Removing service
ziti edge delete service zcat
```
