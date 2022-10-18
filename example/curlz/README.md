# Overview
This example is a zitified cURL (cURLz) example. In this example, a call to a non-zitified endpoint will be made as well
as a call to a zitified endpoint.

This example demonstrates:
* Binding a service

# Requirements
* go 1.19 or later
* an OpenZiti network. If you do not have one, the [quickstart](https://openziti.github.io/ziti/quickstarts/quickstart-overview.html) works well
* OpenZiti CLI to create services and identities on the OpenZiti Network

# Build the example
```
cd <repo-root-dir>/sdk-golang/example/curlz/
go build curlz.go
```

# Setup a cURLz to a non-zitified endpoint
These steps will configure the service using the OpenZiti CLI. At the end of these steps you will have created:
* a service called `www.google.com`
* an identity to connect to (dial) the service
* the service config to connect the service to the overlay
* the service policies required to authorize the identities for bind and dial

Steps:
1. log into Ziti. The host:port and username/password will vary depending on your network.

       ziti edge login localhost:1280 -u admin -p admin
1. Run this script to create everything you need.

       echo Create the service config
       ziti edge create config www.google.com.hostv1 host.v1 '{"protocol":"tcp", "address":"www.google.com","port":'443'}'

       echo Create the service
       ziti edge create service www.google.com --configs "www.google.com.hostv1"
       
       echo Create an identity to make the dial request and enroll it
       ziti edge create identity user curlz -a clients -o curlz.jwt
       ziti edge enroll --jwt curlz.jwt
       
       echo Create service policies
       ziti edge create service-policy www.google.com.dial Dial --service-roles '@www.google.com' --identity-roles '#clients'
       ziti edge create service-policy www.google.com.bind Bind --service-roles '@www.google.com' --identity-roles '@MacBook-Pro.local-edge-router'
       
       echo Create edge router policies
       ziti edge create edge-router-policy curlz-edge-router-policy --edge-router-roles '#all' --identity-roles '#clients,#servers'
       ziti edge create service-edge-router-policy curlz-service-edge-router-policy --edge-router-roles '#all' --service-roles '@www.google.com'
       
       echo Run policy advisor to check
       ziti edge policy-advisor services
1. Run the cURLz example for www.google.com

       ./curlz https://www.google.com curlz.json

## Example Output
The following is the output you'll see from the cURLz request to www.google.com.
```
$ ./curlz https://www.google.com curlz.json
<!doctype html><html itemscope="" itemtype="http://schema.org/WebPage" lang="en">
... <a lot of html code>
</body></html>
```

# Setup a cURLz to a zitified endpoint
These steps will utilize the service and identities created in simple-server to provide an example of using cURLz with a zitified endpoint

Steps:
1. Follow all steps in the simple-service example but **do not** enroll the `simple-client` identity with the Ziti Desktop Edge client
1. cd back into the curlz directory

       cd <repo-root-dir>/sdk-golang/example/curlz/
1. Run this script to create everything you need.

       echo Copy the identity jwt into the current working directory
       cp ../simple-server/simple-client.json .

       echo Enroll the simple-client identity
       ziti edge enroll --jwt simple-client.jwt

1. Run the cURLz example for www.google.com

       ./curlz https://www.google.com curlz.json

## Example Output
The following is the output you'll see from the cURLz request to www.google.com.
```
$ ./curlz http://simpleService.ziti simple-client.json
Who are you?
```

# Teardown
Done with the example? This script will remove everything created during setup.
```
ziti edge login localhost:1280 -u admin -p admin

echo Removing edge router policies
ziti edge delete edge-router-policy curlz-edge-router-policy
ziti edge delete service-edge-router-policy curlz-service-edge-router-policy

echo Removing service policies
ziti edge delete service-policy www.google.com.dial
ziti edge delete service-policy www.google.com.bind

echo Removing service config
ziti edge delete config www.google.com.hostv1

echo Removing identity
ziti edge delete identity curlz

echo Removing service
ziti edge delete service www.google.com
```
If you followed the cURLz to the zitified simple-server endpoint, refer to Teardown in that example README
