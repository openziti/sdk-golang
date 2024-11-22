# Overview
This example illustrates how to send data to, and receive data from a UDP server via OpenZiti.
You will configure an OpenZiti overlay network and run a UDP server that will respond with whatever text it was sent.
The response from the server will be read written to the console.

This example demonstrates a hybrid approach ZTAA --> ZTHA:
* Dialing a service
* Binding a service using a tunneler

## Requirements
* OpenZiti CLI to create services and identities on the OpenZiti Network
* an OpenZiti network. If you have one you'd like to use, great. The guide is written using the 
  `ziti edge quickstart` command.
* All commands are executed relative to the `example` folder

## Build the examples
Refer to the [example README](../README.md) to build the SDK examples

## Run and Configure OpenZiti
The README assumes the `ziti` CLI on your path. If not, supply the full path to the `ziti` executable. This command
will start a ziti overlay network on ports 1280/3022 for use with the rest of the README. The default values will
also be used for username and password. The router from the quickstart is the identity which will offload the OpenZiti
traffic toward the UDP server

In a new terminal run the following command:
```
ziti edge quickstart
```

To configure the overlay, you will need another terminal with `ziti` on the path. Now, add a service for the UDP 
server to be offloaded from the OpenZiti overlay as well as create the identity this example will use:
```
svc_name="udp.relay.example"
edge_router_name="quickstart-router"
ziti edge login localhost:1280 -u admin -p admin -y
ziti edge create config ${svc_name}.hostv1 host.v1 '{"protocol":"udp", "address":"127.0.0.1","port":10001}'
ziti edge create service ${svc_name} --configs "${svc_name}.hostv1"
ziti edge create service-policy ${svc_name}.dial Dial --identity-roles "#${svc_name}.dialers" --service-roles "@${svc_name}"
ziti edge create service-policy ${svc_name}.bind Bind --identity-roles "#${svc_name}.binders" --service-roles "@${svc_name}"

ziti edge create identity ${svc_name}.client -a ${svc_name}.dialers -o ${svc_name}.client.jwt
ziti edge enroll --jwt ${svc_name}.client.jwt

ziti edge update identity ${edge_router_name} -a "${svc_name}.binders"
ziti edge policy-advisor services -q
```

## Run the UDP Server
In the terminal from where you configured the OpenZiti overlay start the UDP server. Make sure you're in the 
`example` folder and run:
```
./build/udp-server
```

You should now have a UDP server that is listening on port 10001 and will respond to UDP messages sent to it.
```
$ ./build/udp-server
Listening on :10001
```

## Run the Example
Make sure the router (or identity) hosting the service establishes a terminator. Issue the following command and verify
a terminator is listed as shown:
```
ziti edge list terminators 'service.name="udp.relay.example"'
```

example output:
```
$ ziti edge list terminators 'service.name="udp.relay.example"'
╭───────────────────────┬───────────────────┬───────────────────┬─────────┬───────────────────────┬──────────┬──────┬────────────┬──────────────╮
│ ID                    │ SERVICE           │ ROUTER            │ BINDING │ ADDRESS               │ IDENTITY │ COST │ PRECEDENCE │ DYNAMIC COST │
├───────────────────────┼───────────────────┼───────────────────┼─────────┼───────────────────────┼──────────┼──────┼────────────┼──────────────┤
│ sNVBPDKuI6q5I0f2PrEc6 │ udp.relay.example │ quickstart-router │ tunnel  │ sNVBPDKuI6q5I0f2PrEc6 │          │    0 │ default    │            0 │
╰───────────────────────┴───────────────────┴───────────────────┴─────────┴───────────────────────┴──────────┴──────┴────────────┴──────────────╯
results: 1-1 of 1
```

With the terminator in place, run the sample
```
./build/udp-offload-client ./udp.relay.example.client.json
```

example output:
```
$ ./build/udp-offload-client ./udp.relay.example.client.json
INFO[0000] found service named: udp.relay.example
INFO[0000] Connected to udp.relay.example successfully.
INFO[0000] You may now type a line to be sent to the server (press enter to send)
INFO[0000] The line will be sent to the reflect server and returned
this is the udp example
wrote 24 bytes
Sent     :this is the udp example
Received: udp server echo: this is the udp example
```