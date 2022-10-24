# Chat Peer-to-Peer Example

This example code is intended to show how addressable terminators can be used from the Go SDK.

## Addressable Terminators

For a quick review of addressable terminators, think about a service that is fronting multiple
destinations. A common example is SSH servers. If you want to treat them all the same, it might
be a lot of work to create a service for each SSH host. Instead, you could make all of them
available under the same service, as long as you had a way to reach the host you wanted when you
used the service.

Terminators in OpenZiti represent a way to find or establish a connection from a router to a
process hosting the service. When establishing a terminator, the hosting process can specify
an instance identifier. This then allows clients to pick which hosting process to connect to.

# Peer-to-Peer Chat

This example show a stripped down P2P chat application, modeled after VoIP. P2P means that
messages aren't proxied through a central server. Rather, every client is both hosting
the service and can dial other clients.

## Binding Code

When each client starts up, it first becomes a service hosting, using the following code:

```
options := ziti.ListenOptions{
    ConnectTimeout:        5 * time.Minute,
    MaxConnections:        3,
    BindUsingEdgeIdentity: true,
}
listener, err := self.context.ListenWithOptions(self.service, &options)
```

By using `BindUsingEdgeIdentity: true`, when this process binds, it will use the id of the
hosting identity as the instance id on the terminator. If an SDK consumer wishes to use an
arbitrary instance id, one can provided in the `Identity` field of `ListenOptions`.
`MaxConnections: 3` means that the SDK will attempt to bind to up to three different edge
routers, creating a terminator on each one. This removes the routers as a single point of failure.

## Dialing Code

On the dialing side, the instance id to connect to can be provided in the `DialOptions`.

```
dialOptions := &ziti.DialOptions{
    Identity:       identity,
    ConnectTimeout: 1 * time.Minute,
    AppData:        []byte("hi there"),
}
conn, err := app.context.DialWithOptions(app.service, dialOptions)
```

The `AppData` provided in `DialOptions` will be passed through and will be available
to the hosting application.

## Listing

In order to know who is available to chat with, an API is available to list terminators
for a given service. This only works if the identity has access to the service. This
call will let the client see what other clients are currently connected. In some
cases it might be preferable to use an external directory, where list terminators call
is only used to show availability.

```
l, _, err := app.context.GetServiceTerminators(app.service, 0, 100)
if err != nil {
    fmt.Printf("error listing call identities %v\n", err)
} else {
    for idx, l := range l {
        fmt.Printf("%v: %v\n", idx+1, l.Identity)
    }
}
```

## Notes

This app is not meant to demonstrate best practices for building command line chat tools.
The UX is minimally functional and is stripped down to focus on the networking elements.

## Setup

Once you have a controller and router running, the chat-p2p can set up your
identities, policies and service for you, using the following command:

```
chat-p2p setup --interactive
```

Note that the `--interactive` parameter is optional.

If you prefer to run the commands yourself, refer to [setup.md](./setup.md)

## Running

Once you have everything created, you can run the call example.

User 1 might start a session as follows:

```
$ chat-p2p -i user1.json 
[   0.000]    INFO main.(*chatPeerToPeer).run: registering to service chat-p2p

Commands:
/connect <identity> | Tries to make a connection to the given identity
/accept             | Accepts an incoming chat connection
/decline            | Declines an incoming chat connection
/bye                | Disconnects the current chat connection
/list               | Lists currently connected identities
/help               | Should this help output
/quit               | Exit the application. You may also use Ctrl-D

user1 > /list    
1: user2
2: user1
user1 > /connect user2
user1 > connecting to user2...
connected to user2
user1 > 
user2: Hello!
user1 > Hi!
user1 > 
```

The corresponding output from User 2 might look like:

```
$ chat-p2p -i user2.json 
[   0.000]    INFO main.(*chatPeerToPeer).run: registering to service chat-p2p

Commands:
/connect <identity> | Tries to make a connection to the given identity
/accept             | Accepts an incoming chat connection
/decline            | Declines an incoming chat connection
/bye                | Disconnects the current chat connection
/list               | Lists currently connected identities
/help               | Should this help output
/quit               | Exit the application. You may also use Ctrl-D

user2 > 
Incoming connection from user1 with appData 'hi there'. Type /accept to accept the connection or /decline to decline it
user2 > /accept

connection accepted and chat now in progress...
user2 > Hello!
user2 > 
user1: Hi!
user2 > 
```