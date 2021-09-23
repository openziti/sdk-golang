# Intro:  

What is zping?  zping replaces the function of icmp ping tool in a ziti network.

It provides an end to end latency measurment between any two ziti identities in a ziti network and like icmp ping will provide the following metrics upon completion of the ping session:

min, max and mean latency and standard deviation as well as % loss.

zping uses the addressable terminator function of ziti to direct ping requests to specific identities.

# Get the code :

Compile from source:

Install golang for your platform follow instructions at https://golang.org

Linux:

   Create a dir
```
   mkdir zitiapps
```
```
   $ cd zitiapps
```   
```   
   $ git clone https://github.com/openziti/sdk-golang.git
```
```
   $ cd sdk-golang/example/zping
```
```
   $ go build zping
```

# Setup the Network and the Ziti Service :

![Diagram](network.png)

1. Create or use an existing ziti network with at least one edge router.

2. Create at least two ziti identities and give them a common identity role i.e. #ping 

      e.g. zitiendpoint1, zitiendpoint2

3. Create a simple sdk service named “ziti-ping” this is the default service zping looks for but can be          

   overriden  with the -s command line flag.

4. Create a bind policy with identityRoles set to [#ping] and serviceroles set to [@ziti-ping].

5. Create a dial service policy with identityRoles set to [#ping] and serviceroles set to [@ziti-ping].

6. Ensure that you have created appropriate edge-router and service-edge-router policies allowing the identities access
   edge-router(s) and the edge-routers access to the service.

7. Create an AppWAN and enter @ziti-ping in the service attributes and #ping in the “Endpoint Attributes”

8. Download the zpingendpoint1.jwt, zpingendpoint2.jwt

9. Distribute the zping binary to the endpoint(s) you wish to run on

10. Enroll the endpoints with the zping binary i.e. 
```
    $ ./zping enroll -j zitiendpoint1.jwt

      INFO[0000] generating 4096 bit RSA key                  

      INFO[0002] enrolled successfully. identity file written to: zpingendpoint1.json
```    
```
    $ ./zping enroll -j zpingendpoint2.jwt

      INFO[0000] generating 4096 bit RSA key                  

      INFO[0002] enrolled successfully. identity file written to: zpingendpoint2.json
```
11. On each machine in run either in background or a separate window in server mode
```
    $ ./zping server -c zpingendpoint1.json &
      [1] 4123
      INFO[0000] binding service ziti-ping
      
      zpingendpoint1 now serving
      
      INFO[0000] connection to edge router using token 1de2f02e-62fe-44fb-bebb-e2d21a82d13f            
```
```
    $ ./zping server -c zpingendpoint2.json &
      [1] 5176
      INFO[0000] binding service ziti-ping                    

      zpingendpoint2 now serving

      INFO[0000] connection to edge router using token d472f74c-97af-426a-a07f-7ecd907a2013 
```
12. Send 5 zpings from zpingclient2 to zpingclient1
```
      $ ./zping client -c zitiendpoint2.json -i zitiendpoint1 -n 5
        INFO[0000] connection to edge router using token b78cab88-fa22-4d49-906f-ddf101b63b88 
        INFO[0566] new connection                               

        Sending 100 byte pings to zpingendpoint1:

        100 bytes from zpingendpoint1: ziti_seq=1 time=76.558ms
        100 bytes from zpingendpoint1: ziti_seq=2 time=75.597ms
        100 bytes from zpingendpoint1: ziti_seq=3 time=76.209ms
        100 bytes from zpingendpoint1: ziti_seq=4 time=76.332ms
        100 bytes from zpingendpoint1: ziti_seq=5 time=76.849ms
        
        --- zpingendpoint1 ping statistics ---
        5 packets transmitted and 5 packets recieved, 0.00% packet loss
        round-trip min/max/avg/stddev 75.597/76.849/76.309/0.417 ms
```
