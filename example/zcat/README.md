# Overview
This example illustrates how to embed zero trust connectivity into a Netcat like application. There are two parts, part
 1 shows how to use zcat with a broadcast style messaging service. Part two shows how to use 
 [addressable terminators](https://github.com/openziti/fabric/wiki/Addressable-Terminators) to direct messages to 
 specific endpoints.

This example demonstrates:
* Dialing a service
* Binding a service
* Using [addressable terminators](https://github.com/openziti/fabric/wiki/Addressable-Terminators)

## Requirements
* an OpenZiti network. If you do not have one, you can use one of the [quickstarts](https://netfoundry.io/docs/openziti/learn/quickstarts/) to set one up.
* OpenZiti CLI to create services and identities on the OpenZiti Network
* The [netcat](https://netcat.sourceforge.net/) CLI tool

## Build the examples
Refer to the [example README](../README.md) to build the SDK examples

## Part 1 Setup: zcat to a non-zitified endpoint
These steps will configure the service using the OpenZiti CLI. At the end of these steps you will have created:
* a service called `zcat`
* an identity to dial the service
* the service config to connect the service to the overlay
* the service policies required to authorize the identities for bind and dial

Steps:
1. Log into OpenZiti. The host:port and username/password will vary depending on your network.

       ziti edge login localhost:1280 -u admin -p admin
1. Give your edge router an attribute to be used in this example

       ziti edge list edge-routers
       ziti edge update identity <name-of-edge-router> -a 'zcat.servers'
1. Run this script to create everything you need.

       cd <repo-root-dir>/example/build

       echo Create the service config
       ziti edge create config zcat.hostv1 host.v1 '{"protocol":"tcp", "address":"localhost","port":'1234'}'

       echo Create the service
       ziti edge create service zcat --role-attributes zcat-service --configs "zcat.hostv1"
       
       echo Create an identity for the client side to dial with
       ziti edge create identity device zcat-client -a zcat.clients -o zcat-client.jwt
       ziti edge enroll --jwt zcat-client.jwt
       
       echo Create service policies
       ziti edge create service-policy zcat.dial Dial --identity-roles '#zcat.clients' --service-roles '#zcat-service'
       ziti edge create service-policy zcat.bind Bind --identity-roles '#zcat.servers' --service-roles '#zcat-service'
       
       echo Run policy advisor to check
       ziti edge policy-advisor services
1. Run a netcat listener (-l creates a listener and -k keeps the listener running when connections are closed). The 
   netcat listener should be run on the device hosting your edge router.

       nc -lk localhost 1234
1. Run the zcat application and send something to the server

       ./zcat zcat -i zcat-client.json

### Example output
The following is the output you'll see from the server and client side after running the previous commands.

#### Server
```shell
$ nc -lk localhost 1234
hello
```
#### Client
```shell
$ ./zcat zcat -i zcat-client.json
[   0.224]    INFO main.runFunc: connected
hello
```

### Teardown Part 1
Done with the example? This script will remove everything created during setup for part 1.
```shell
ziti edge login localhost:1280 -u admin -p admin

echo Removing service policies
ziti edge delete service-policy zcat.dial
ziti edge delete service-policy zcat.bind

echo Removing service config
ziti edge delete config zcat.hostv1

echo Removing identities
ziti edge delete identity zcat-client

echo Removing service
ziti edge delete service zcat
```
## Part 2 Setup: zcat to a zitified endpoint
These steps will configure the service using the OpenZiti CLI. At the end of these steps you will have created:
* a service called `zcat.addressable`
* two identities, one to dial the service and one to bind to the service
* the service config to connect the service to the overlay
* the service policies required to authorize the identities for bind and dial

Steps:
1. Log into OpenZiti. The host:port and username/password will vary depending on your network.

       ziti edge login localhost:1280 -u admin -p admin
1. If you didn't perform "Part 1" of this exercise, give your edge router an attribute to be used in this example

       ziti edge list edge-routers
       ziti edge update identity <name-of-edge-router> -a 'zcat.servers'
1. Run this script to create everything you need.

       cd <repo-root-dir>/example/build

       echo Create the service config
       ziti edge create config zcat.hostv1.addressable host.v1 '{"protocol":"tcp", "address":"localhost","port":'1234', "listenOptions": {"bindUsingEdgeIdentity":true}}'

       echo Create the service
       ziti edge create service zcat.addressable --role-attributes zcat-addressable --configs "zcat.hostv1.addressable"
       
       echo Create two identities, one for the server side, one for the client side
       ziti edge create identity device zcat-client -a zcat.clients -o zcat-client.jwt
       ziti edge enroll --jwt zcat-client.jwt
       ziti edge create identity user example.user -a zcat.servers -o example.user.jwt
       
       echo Create service policies
       ziti edge create service-policy zcat.addressable.dial Dial --service-roles "#zcat-addressable" --identity-roles "#zcat.clients"
       ziti edge create service-policy zcat.addressable.bind Bind --service-roles "#zcat-addressable" --identity-roles "#zcat.servers"
       
       echo Run policy advisor to check
       ziti edge policy-advisor services
1. Enroll the example.user identity in your local tunneler
   1. Refer to [enrolling documentation](https://netfoundry.io/docs/openziti/learn/core-concepts/identities/enrolling/) for details

1. Run a netcat listener

       nc -lk localhost 1234
1. Run the zcat application and send something to the edge router

       ./zcat zcat.addressable <name-of-edge-router> -i zcat-client.json
1. Run the zcat application and send something to example.user

       ./zcat zcat.addressable example.user -i zcat-client.json
### Example output
The following is the output you'll see from the server and client side after running the previous commands.
#### Server
```shell
$ nc -lk localhost 1234
hello
hello
```
#### Client connecting to edge router
```shell
$ ./zcat zcat.addressable <name-of-edge-router> -i zcat-client.json
[   0.221]    INFO main.runFunc: connected
hello
```
#### Client connecting to `example.user`
```shell
$ ./zcat zcat.addressable example.user -i zcat-client.json
[   0.223]    INFO main.runFunc: connected
hello
```
**Note** that if the tunneler `example.user` is using to connect with is turned off, an error will be displayed. This 
can be used as proof that sending directly to `example.user` with an addressable terminator was attempted but due to the 
user not being bound to the service, the message failed to send since there was no terminator for that user.

#### Example error output
```shell
./zcat zcat.addressable example.user -i zcat-client.json
[   0.223]   FATAL main.runFunc: {error=[unable to dial service 'zcat.addressable': dial failed: service 5VN4H4YQikdAwPFN3XWhYZ has no terminators for instanceId example.user]} unable to dial service: 'zcat.addressable'
```
### Teardown Part 2
Done with the example? This script will remove everything created during setup for part 2.
You will have to manually remove the identity from your Ziti Desktop Edge application.
```shell
ziti edge login localhost:1280 -u admin -p admin

echo Removing service policies
ziti edge delete service-policy zcat.addressable.dial
ziti edge delete service-policy zcat.addressable.bind

echo Removing service config
ziti edge delete config zcat.hostv1.addressable

echo Removing identity
ziti edge delete identity zcat-client

echo Removing service
ziti edge delete service zcat.addressable
```