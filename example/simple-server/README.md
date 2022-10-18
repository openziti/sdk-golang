# Overview
This example is a simple server showing how to create server side code in an OpenZiti Network. A server is spun up to 
serve plain HTTP requests and a Zitified server is spun up to serve zitified requests. This example attaches one server 
to the underlay (HTTP server) and a second server on the overlay (Ziti Service).

This example demonstrates:
* Binding a service and listening for HTTP connections
* Accessing the service via a tunneler
  * [Ziti Desktop Edge for Windows](https://github.com/openziti/desktop-edge-win/releases)
  * [Ziti Desktop Edge for Mac](https://apps.apple.com/app/id1460484572)
  * [Ziti Desktop Edge for Linux](https://openziti.github.io/ziti/clients/linux.html)

# Requirements
* go 1.19 or later
* an OpenZiti network. If you do not have one, the [quickstart](https://openziti.github.io/ziti/quickstarts/quickstart-overview.html) works well
* OpenZiti CLI to create services and identities on the OpenZiti Network
* Have the appropriate Ziti Desktop Edge for your operating system
  * [Ziti Desktop Edge for Windows](https://github.com/openziti/desktop-edge-win/releases)
  * [Ziti Desktop Edge for Mac](https://apps.apple.com/app/id1460484572)
  * [Ziti Desktop Edge for Linux](https://openziti.github.io/ziti/clients/linux.html)

# Build the example
```
cd <repo-root-dir>/sdk-golang/example/simple-server/
go build main.go
```

# Setup using the OpenZiti CLI
These steps will configure the service using the OpenZiti CLI. At the end of these steps you will have created:
* a service called `simpleService`
* an identity to host (bind) the service
* an identity to connect to (dial) the service
* the service policies required to authorize the identities for bind and dial

Steps:
1. log into Ziti. The host:port and username/password will vary depending on your network.

       ziti edge login localhost:1280 -u admin -p admin
1. Run this script to create everything you need.

       echo Create the service configs
       ziti edge create config simple.hostv1 host.v1 '{"protocol":"tcp", "address":"localhost","port":'8080'}'
       ziti edge create config simple.interceptv1 intercept.v1 '{"protocols":["tcp"],"addresses":["simpleService.ziti"], "portRanges":[{"low":'8080', "high":'8080'}]}'

       echo Create the service
       ziti edge create service simpleService --configs "simple.hostv1,simple.interceptv1" --role-attributes simple-service
       
       echo Create two identities and enroll the server
       ziti edge create identity user simple-client -a clients -o simple-client.jwt
       ziti edge create identity device simple-server -a servers -o simple-server.jwt
       ziti edge enroll --jwt simple-server.jwt
       
       echo Create service policies
       ziti edge create service-policy simple-client-dial Dial --identity-roles '#clients' --service-roles '#simple-service'
       ziti edge create service-policy simple-client-bind Bind --identity-roles '#servers' --service-roles '#simple-service'
       
       echo Create edge router policies
       ziti edge create edge-router-policy simple-edge-router-policy --edge-router-roles '#all' --identity-roles '#clients,#servers'
       ziti edge create service-edge-router-policy simple-service-edge-router-policy --edge-router-roles '#all' --service-roles '#simple-service'
       
       echo Run policy advisor to check
       ziti edge policy-advisor services
1. Run the server.

       ./simple-server simple-server.json simpleService

1. Enroll the client identity
   1. Open your Ziti Desktop Edge application
   1. Choose to add an identity
   1. Navigate to, and select, the `jwt` of the client identity (simple-client.jwt)
   1. Click the Enroll button to enroll the client identity.

1. Issue cURL commands to see the server side responses in action
   1. curl http://localhost:8080?name=client
   2. curl http://simpleService.ziti:8080?name=client

## Example output
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

# Teardown
Done with the example? This script will remove everything created during setup.
You will have to manually remove the identity from your Ziti Desktop Edge application.
```
ziti edge login localhost:1280 -u admin -p admin

echo Removing edge router policies
ziti edge delete edge-router-policy simple-edge-router-policy
ziti edge delete service-edge-router-policy simple-service-edge-router-policy

echo Removing service policies
ziti edge delete service-policy simple-client-dial
ziti edge delete service-policy simple-client-bind

echo Removing service configs
ziti edge delete config simple.hostv1
ziti edge delete config simple.interceptv1

echo Removing identities
ziti edge delete identity simple-client
ziti edge delete identity simple-server

echo Removing service
ziti edge delete service simpleService
```
