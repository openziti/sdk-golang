# Release 0.22.0

- Add SessionRefreshInterval to DialOptions, with a default of 1 hour.

# Release 0.21.0

- New `ListenOptions` field: `WaitForNEstablishedListeners`. Allows specifying that you want at least N listeners to be established before the `Listen` method returns. Defaults to 0.

# Release 0.20.145

- New `Context` API method: `RefreshService`, which allows refreshing a single service, when that's all that's needed.

# Release 0.20.59

- SDK context's will now use the properly prefixed Edge Client API Path for enrollment configurations. Previous versions
  relied upon legacy path support in scenarios where Ziti Context configurations were generated from an enrollment JWT.
- Added `edge_apis.ClientUrl(hostname string)` and `edge_apis.ManagementUrl(hostname string)` to convert hostnames
  to fully prefixed API URls.

# Release 0.20.52 - 0.20.58

- minor bug fixes
- dependency updates


# Release 0.20.51

## WHat's New

* Edge Router Filter Options - now possible to filter Edge Routers based on connection URL

## Edge Router Filter Options

When creating Ziti SDK Context instances, the options argument can now contain an `EdgeRouterUrlFilter` function
that takes in a string URL and returns a boolean to determine if the context will use that connection string
to connect to the Edge Router. This is useful when operating in restricted environments, GoLang WASM, where
some connection methods are no allowed (i.e. tcp/tls vs ws/wss).

```go
	cfg := &ziti.Config{
		ZtAPI:       "https://localhost:1280/edge/client/v1",
		Credentials: credentials,
	}
	ctx, err := ziti.NewContextWithOpts(cfg, &ziti.Options{
		EdgeRouterUrlFilter: func(addr string) bool {
			return strings.HasPrefix(addr,"wss")
		},
	})
```



# Release 0.20.50

## What's New

`ziti.Options` has a new field: `EdgeRouterUrlFilter func(string) bool`. This allows filtering which edge router URLS you
want the SDK to try and connect to. In most cases, filtering will be done by protocol. If no filter is provided, all
URL will be used.

# Release 0.20.48

## What's New

* Change log - This change log was added and is a reflection of all changes from `v0.20.0` to `v0.20.23`
* Flattened Config Name Space - Reduce collisions for implementors by removing `config` package
* New Authentication Options - alters the configuration options used to instantiate Ziti SDK contexts. This impacts
  context instantiation signatures.
* New Internal Edge Client & Management clients using `edge-apis`
    * `edge-apis` - A new root level package, `edge-apis` has been added which provides a thin wrapper around the
      go-swagger
      generated Edge Client and Management APIs.
    * Usage of the `edge-apis` package is not required to use the OpenZiti Golang SDK but is exposed for those who which
      to.
* API Session Certificates - API Session Certificates allow authentication mechanisms that are not inherently backed by
  a x509 certificate to obtain ephemeral x509 certificate and interact with an OpenZiti network.
* Event API - The GoLang SDK now supports an eventing interface that allows implementors to register listeners
* Browser WASM Compilation support - Compiling the GO SDK to run in WASM browser environments is now supported.

## Flattened Name Space

Previously, the GoLang SDK provided a package named `config` which would collide when used in other projects that also
contained variables or packages named config. To reduce collisions, the `config` package has been removed. This has
the following impact:

- The type `config.Config` is now `ziti.Config` for importers
- Configuration instantiation is no long `config.New*()` but rather `ziti.NewConfig*()`
- Context instantiation is no longer `ziti.New*()` but rather `ziti.NewContext*()`

## New Authentication Options

It is now possible to create an OpenZiti GoLang SDK Context by using alternative authentication mechanisms such as
raw private/public keys, JWTs, and Username Passwords (UPDB) in addition to the original configuration file approach.
This capability is provided by the `edge-apis` package. To make use of these new option, configure them on
a `ziti.Config`

```go
creds := edge_apis.NewJwtCredentials(jwtToken)
creds.CaPool = caPool

cfg := &ziti.Config{
ZtAPI:       "https://localhost:1280/edge/client/v1",
Credentials: creds,
}
ctx, err := ziti.NewContext(cfg)
```

Previous file based implementations may still use identity files:

```go
ctx, err := NewContextFromFile("identity.json")
```

## `edge-apis`

The packaged `edge-apis` can be used as a standalone way of interacting with the OpenZiti Edge Client and Management
APIs. They core API functionality is maintained in `openziti/edge-apis` and contains the raw GoSwagger generated API
clients. The clients in this repository have been wrapped with a thin layer to make authentication easier.

To use the GoLang Ziti SDK one does not have to use this package directly. The Golang SDK uses this package under the
hood.

To create an instance of either the Client or Management clients, a Credential instance is required. The following
types are currently supported:

- `IdentityCredentials` - JSON configuration that embeds the controller URL, public/private keys and location. This was
  the previous only authentication mechanism supported by the Golang SDK
- `JwtCredentials` - an externally integrating solution that uses controller `external-jwt-signers` to integrate with
  any JWT
  providing IdP
- `CertCredentials` - Raw handling of public and private key GoLang types
- `UpdbCredentials` - A username/password combination

Creating new Credential instances is enabled through direct instantiation or via helper functions. Here are two
examples:

```go
creds := edge_apis.NewCertCredentials([]*x509.Certificate{testIdCerts.cert}, testIdCerts.key)
creds.CaPool = ziti.GetControllerWellKnownCaPool("https://example.com:1280")
```

```go
creds := edge_apis.New([]*x509.Certificate{testIdCerts.cert}, testIdCerts.key)
creds.CaPool = ziti.GetControllerWellKnownCaPool("https://example.com:1280")
```

After a credentials instance is created, a client may be created that will authenticate and provide API access.

```go
creds := edge_apis.New([]*x509.Certificate{testIdCerts.cert}, testIdCerts.key)
creds.CaPool = ziti.GetControllerWellKnownCaPool("https://example.com:1280")

client := edge_apis.NewClientApiClient(clientApiUrl, nil)
apiSession, err := client.Authenticate(creds, nil)

fmt.Printf("identity name: %s", apiSession.Identity.Name)

resp, err := client.API.Service.ListServices(service2.NewListServicesParams(), nil)
```

## API Session Certificates

OpenZiti Controllers support the creation of ephemeral, API Session scoped, x509 Certificates for fully authenticated
API Sessions.
These certificates are created automatically by the GoLang SDK when the authentication mechanism provided to the context
is not backed by a x509 Certificate.

## Event API

OpenZiti Context's returned now support an `Event()` function which exposes the following function calls:

```go
// AddServiceAddedListener adds an event listener for the EventServiceAdded event and returns a function to remove
// the listener. It is emitted any time a new service definition is received. The service detail provided is the
// service that was added.
AddServiceAddedListener(func(Context, *rest_model.ServiceDetail)) func()

// AddServiceChangedListener adds an event listener for the EventServiceChanged event and returns a function to remove
// the listener. It is emitted any time a known service definition is updated with new values. The service detail
// provided is the service that was changed.
AddServiceChangedListener(func(Context, *rest_model.ServiceDetail)) func()

// AddServiceRemovedListener adds an event listener for the EventServiceRemoved event and returns a function to remove
// the listener. It is emitted any time known service definition is no longer accessible. The service detail
// provided is the service that was removed.
AddServiceRemovedListener(func(Context, *rest_model.ServiceDetail)) func()

// AddRouterConnectedListener adds an event listener for the EventRouterConnected event and returns a function to remove
// the listener. It is emitted any time a router connection is established. The strings provided are router name and connection address.
AddRouterConnectedListener(func(ztx Context, name string, addr string)) func()

// AddRouterDisconnectedListener adds an event listener for the EventRouterDisconnected event and returns a function to remove
// the listener. It is emitted any time a router connection is closed. The strings provided are router name and connection address.
AddRouterDisconnectedListener(func(ztx Context, name string, addr string)) func()

// AddMfaTotpCodeListener adds an event listener for the EventMfaTotpCode event and returns a function to remove
// the listener. It is emitted any time the currently authenticated API Session requires an MFA TOTP Code for
// authentication. The authentication query detail and an MfaCodeResponse function are provided. The MfaCodeResponse
// should be invoked to answer the MFA TOTP challenge.
//
// Authentication challenges for MFA are modeled as authentication queries, and is provided to listeners for
// informational purposes. This event handler is a specific authentication query that responds to the internal Ziti
// MFA TOTP challenge only. All authentication queries, including MFA TOTP ones, are also available through
// AddAuthQueryListener, but does not provide typed response callbacks.
AddMfaTotpCodeListener(func(Context, *rest_model.AuthQueryDetail, MfaCodeResponse)) func()

// AddAuthQueryListener adds an event listener for the EventAuthQuery event and returns a function to remove
// the listener. The event is emitted any time the current API Session is required to pass additional authentication
// challenges - which enabled MFA functionality.
AddAuthQueryListener(func(Context, *rest_model.AuthQueryDetail)) func()

// AddAuthenticationStatePartialListener adds an event listener for the EventAuthenticationStatePartial event and
// returns a function to remove the listener. Partial authentication occurs when there are unmet authentication
// queries - which are defined by the authentication policy associated with the identity. The
// EventAuthQuery or EventMfaTotpCode events will also coincide with this event. Additionally, the authentication
// queries that triggered this event are available on the API Session detail in the `AuthQueries` field.
//
// In the partially authenticated state, a context will have reduced capabilities. It will not be able to
// update/list services, create service sessions, etc. It will be able to enroll in TOTP MFA and answer
// authentication queries.
//
// One all authentication queries are answered, the EventAuthenticationStateFull event will be emitted. For
// identities that do not have secondary authentication challenges associated with them, this even will never
// be emitted.
AddAuthenticationStatePartialListener(func(Context, *rest_model.CurrentAPISessionDetail)) func()

// AddAuthenticationStateFullListener adds an event listener for the EventAuthenticationStateFull event and
// returns a function to remove the listener. Full authentication occurs when there are no unmet authentication
// queries - which are defined by the authentication policy associated with the identity. In a fully authenticated
// state, the context will be able to perform all client actions.
AddAuthenticationStateFullListener(func(Context, *rest_model.CurrentAPISessionDetail)) func()

// AddAuthenticationStateUnauthenticatedListener adds an event listener for the EventAuthenticationStateUnauthenticated
// event and returns a function to remove the listener. The unauthenticated state occurs when the API session
// currently being used is no longer valid. API Sessions may become invalid due to prolonged inactivity due to
// network disconnection, the host machine entering a power saving/sleep mode, etc. It may also occur due to
// administrative action such as removing specific API Sessions or removing entire identities.
//
// The API Session detail provided to the listener may be nil. If it is not nil, the API Session detail is the
// now expired API Session.
AddAuthenticationStateUnauthenticatedListener(func(Context, *rest_model.CurrentAPISessionDetail)) func()
```

The above functions allow for the addition of strongly typed event handlers and removal of those listeners with the 
returned `func()`. These functions do not require knowing the event names or handling type assertions as the events are
emitted.

The underlying event functionality is provided by `github.com/kataras/go-events` which uses a weakly typed arguments
for events. The `go-events` interface for event emitters is available for use and will require usage of the documented
event names in `ziti/events.go`.

All events, either through the strongly typed or weakly typed interface, are called synchronously. Performing operations
that take longer than a few milliseconds is not suggested. If necessary, when your event handler is called spawn a 
goroutine to offload any extended processing.

Synchronous Event:
```go
ctx, err := ziti.NewContext(cfg)
ctx.Events().AddServiceAddedListener(func(detail *rest_model.ServiceDetail) {
    fmt.Printf("New service %s", *detail.Name)
})
```

Asynchronous Event:
```go
ctx, err := ziti.NewContext(cfg)
ctx.Events().AddServiceAddedListener(func(detail *rest_model.ServiceDetail) {
    go func(){
		fmt.Printf("New service %s", *detail.Name
    }()
})
```

# Browser WASM Compilation support

Compiling projects that use the GO SDK with `js` tag will now alter internal components to deal with running in a 
browser environment. This includes enabling WebSocket Secure (WSS) connections to Edge Routers.

`go build ./my-project -tags=js`
