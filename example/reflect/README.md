# Running The Reflect Example

## Ziti Network Setup
### Create A Ziti Network
You will need to have ziti executables available to run from your command line. If you do not have them, the easiest way to set yourself up is to run ziti express install.

To run express install, check out the instructions [here](https://openziti.github.io/ziti/quickstarts/network/local-no-docker.html)

If running express install, you will need to add the ziti binaries to your path which you can do with the following command.
```
export PATH="$PATH:${ZITI_BIN_DIR}"
```

### Log Into The Ziti Network
#### Start The Network Devices
Start up your controller (which is automatically set up by the express install). 

* If you used the express install then simply run `startZitiController`
* Otherwise, the command would be as follows
```
ziti-controller run "path-to-controller-config.yaml"
```

Start up your router (which is also automatically set up by the express install).

* If you used the express install then simply run `startZitiController`
* Otherwise, the command would be as follows
```
ziti-router run "path-to-edge-router-config.yaml"
```

#### Log Into Ziti Controller
* If you used express install then simply run `zitiLogin`
* Otherwise, the command would be as follows
```
ziti edge login <controller-hostname>:<controller-port> -u <username> -p <password -c <cert-string>
```

## Setup

Before continuing, it is recommended that you `cd` into the example project directory.
```
cd <repo-root-dir>/sdk-golang/example/reflect/
```

### Create The Identities
You will need identities for both the client and the server.

To create the identities, run the following:
```
ziti edge create identity device client -o client.jwt
ziti edge create identity device server -o server.jwt
```

### Enroll The Identities
The identites need to be enrolled so they can be found by the controller.

To enroll the identities, run the following:
```
ziti edge enroll -j client.jwt
ziti edge enroll -j server.jwt
```

### Create A Service
Now a service is needed to provide access to traffic on the application.

To create the service, run the following:
```
ziti edge create service reflect_svc
```

### Update The Service Policy
The service policy needs to be updated to handle traffic between the client and the server.

To update the service policy, run the following:
```
ziti edge create service-policy reflect-dial Dial --identity-roles "@client" --service-roles "@reflect_svc"
ziti edge create service-policy reflect-bind Bind --identity-roles "@server" --service-roles "@reflect_svc"
```

## Running The Example

### Build The Project
If you haven't already, `cd` into the reflect example directory.
```
cd <repo-root-dir>/sdk-golang/example/reflect/
```

Now build the executable. After which, you should see an executable named `main` in the current directory.
```
go build main.go
```

### Start the client and server
The final step is to start up the client and server processes for the reflect example. The server must be up first:
```
./main server -i server.json -s reflect_svc
```

In a new bash window, start up the client:
```
./main client -i client.json -s reflect_svc
```

#### Example output
**Server**
```
$ ./main server -i server.json -s reflect_svc
INFO    ready to accept connections                  
INFO    connection to edge router using api session token ae0a33d9-e745-4b8e-b7df-9a5c850e2222 
INFO    new connection accepted                      
INFO    about to read a string :                     
INFO                      read : Hello Ziti          
INFO           responding with : you sent me: Hello Ziti 
```
**Client**
```
$ ./main client -i client.json -s reflect_svc
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