# Overview
This example is a simple reflect server. The client sends some bytes to the server, and the server responds with those bytes. 

This example demonstrates:
* Binding a service and listening for connections
* Dialing a service
* Bidirectional communication over the Open Ziti network overlay

## Requirements
* an OpenZiti network. If you do not have one, the [quickstarts](https://netfoundry.io/docs/openziti/learn/quickstarts/) works well
* OpenZiti cli or Zac to create services and identities on the OpenZiti network 

## Build the examples
Refer to the [example README](../README.md) to build the SDK examples

## Setup using the OpenZiti CLI
These steps will configure the reflect service using the OpenZiti CLI. At the end of these steps you will have created:
* a service called `reflectService`
* an identity to host (bind) the service
* an identity to connect to (dial) the service
* the service policies required to run the application

Steps:
1. Log into OpenZiti. The host:port and username/password will vary depending on your network.

       ziti edge login localhost:1280 -u admin -p admin
2. Run this script to create everything you need.

       echo Changing to build directory
       cd $ZITI_SDK_BUILD_DIR
       
       echo Create the service
       ziti edge create service reflectService --role-attributes reflect-service
       
       echo Create and enroll two identities
       ziti edge create identity device reflect-client -a reflect.clients -o reflect-client.jwt
       ziti edge create identity device reflect-server -a reflect.servers -o reflect-server.jwt
       ziti edge enroll --jwt reflect-client.jwt
       ziti edge enroll --jwt reflect-server.jwt
       
       echo Create service policies
       ziti edge create service-policy reflect-client-dial Dial --identity-roles '#reflect.clients' --service-roles '#reflect-service'
       ziti edge create service-policy reflect-client-bind Bind --identity-roles '#reflect.servers' --service-roles '#reflect-service'
       
       echo Run policy advisor to check
       ziti edge policy-advisor services
3. Run the server.

       ./reflect server -i reflect-server.json -s reflectService
4. Run the client.

       ./reflect client -i reflect-client.json -s reflectService
### Example output
**Server**
```shell
$ ./reflect server -i server.json -s reflect_svc
INFO    ready to accept connections                  
INFO    connection to edge router using api session token ae0a33d9-e745-4b8e-b7df-9a5c850e2222 
INFO    new connection accepted                      
INFO    about to read a string :                     
INFO                      read : Hello Ziti          
INFO           responding with : you sent me: Hello Ziti 
```
**Client**
```shell
$ ./reflect client -i client.json -s reflect_svc
INFO    found service named: reflect_svc             
WARNING no config of type ziti-tunneler-client.v1 was found 
INFO    connection to edge router using api session token b97826dc-5314-44fb-9407-b6177f409b68 
INFO    Connected to reflect_svc successfully.       
INFO    You may now type a line to be sent to the server (press enter to send) 
INFO    The line will be sent to the reflect server and returned 
Hello Ziti
wrote 11 bytes
Sent    :Hello Ziti
Received: you sent me: Hello Ziti
```

## Teardown
Done with the example? This script will remove everything created during setup.
```shell
echo Removing service policies
ziti edge delete service-policy reflect-client-dial
ziti edge delete service-policy reflect-client-bind

echo Removing identities
ziti edge delete identity reflect-client
ziti edge delete identity reflect-server

echo Removing service
ziti edge delete service reflectService
```
