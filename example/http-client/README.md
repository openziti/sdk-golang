# Overview

This example demonstrates a zitified HTTP client.

This example demonstrates:

* Dialing a service by intercept address.

## Requirements

* an OpenZiti network. If you do not have one, you can use one of the [quickstarts](https://netfoundry.io/docs/openziti/learn/quickstarts/) to set one up.
* OpenZiti CLI to create services and identities on the OpenZiti Network

## Build the example

Refer to the [example README](../README.md) to build the SDK examples

## Part 1: Set up a cURLz to a non-zitified endpoint

These steps will configure the service using the OpenZiti CLI. In this example, the traffic starts on the overlay zero
trust network and then is offloaded onto the underlay network.

### Part 1 Architecture Overview

![image](unzitified.png)

At the end of these steps you will have created:

* a service called `web.endpoint`
* an identity to connect to (dial) the service
* the service config to connect the service to the overlay
* the service policies required to authorize the identities for bind and dial

Steps:

1. log into Ziti. The host:port and username/password will vary depending on your network.

    ```bash
    ziti edge login localhost:1280 -u admin -p admin
    ```

1. Determine your edge router's name and populate this environment variable with it.

    ```bash
    ziti edge list edge-routers
    export ZITI_EDGE_ROUTER=<name-of-edge-router>
    ```

1. Run this script to create everything you need.

    ```bash
    cd <repo-root-dir>/example/build
 
    echo Create the service config
    ziti edge create config httpbin.hostv1 host.v1 '{"protocol":"tcp", "address":"httpbin.org","port":80}'
    ziti edge create config httpbin.clientv1 intercept.v1 '{"protocols":["tcp"], "addresses":["httpbin.ziti"],"portRanges":[{"low":80,"high":80}]}'
 
    echo Create the service
    ziti edge create service ziti.httpbin --configs "httpbin.hostv1,httpbin.clientv1"
    
    echo Create an identity to make the dial request and enroll it
    ziti edge create identity user http-client -a clients -o http-client.jwt
    ziti edge enroll --jwt http-client.jwt
    
    echo Create service policies
    ziti edge create service-policy ziti.httpbin.dial Dial --service-roles "@ziti.httpbin" --identity-roles "#clients"
    ziti edge create service-policy ziti.httpbin.bind Bind --service-roles "@ziti.httpbin" --identity-roles "@${ZITI_EDGE_ROUTER}"
    
    echo Create edge router policies
    ziti edge create edge-router-policy ziti.httpbin-edge-router-policy --edge-router-roles '#all' --identity-roles '#clients,#servers'
    ziti edge create service-edge-router-policy ziti.httpbin-service-edge-router-policy --edge-router-roles '#all' --service-roles '@ziti.httpbin'
    
    echo Run policy advisor to check
    ziti edge policy-advisor services
    ```

1. Run the `http-client` example for service `ziti.httpbin` using intercept address `tcp:httpbin.ziti:80`

    ```bash
    ZITI_IDENTITIES=http-client.json ./http-client http://httpbin.ziti
    ```

### Example Output

The following is the output you'll see.

```bash
export ZITI_IDENTITIES=http-client.json
$ ./http-client http://httpbin.ziti/json
{
  "slideshow": {
    "author": "Yours Truly", 
    "date": "date of publication", 
    "slides": [
      {
        "title": "Wake up to WonderWidgets!", 
        "type": "all"
      }, 
      {
        "items": [
          "Why <em>WonderWidgets</em> are great", 
          "Who <em>buys</em> WonderWidgets"
        ], 
        "title": "Overview", 
        "type": "all"
      }
    ], 
    "title": "Sample Slide Show"
  }
}
```
