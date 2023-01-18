# jwtchat

A set of three binaries used to demonstrate the OpenZiti GoLang SDK using external JWT signers to athenticate.

# Binaries

## jwtchat-idp

Stands up an OIDC compliant OpenId Provider (OP) that allows all OIDC flows. This example uses Client Credentials.

It is run without any arguments and host the OPIDC API on `localhost:9998`

## jwtchat-client

Attempts to contact a controller listening on `localhost:1280` and an OIDC compliant provider on `localhost:9998`.

It is run without any arguments and does not open any ports. It attempts to connection/dial a service named `jwtchat`

It will attempt to authenticate with the OIDC provider as:

- username: `cid1`
- password: `cid1secreat`


## jwtchat-server

Attempts to contact a controller listening on `localhost:1280` and an OIDC compliant provider on `localhost:9998`.

It is run without any arguments and does not open any ports. It attempts to host/bind a service named `jwtchat`

It will attempt to authenticate with the OIDC provider as:

- username: `cid2`
- password: `cid2secreat`

# Setup

1) Stand up an OpenZiti network
2) Create at least one Edge Router
3) Create two identities (client, server)
   1) ensure they have the externalId's set to `cid1` (client) and `cid2` (server)
   2) give them both an attribute named `jwtchat`
4) Create a service named `jwtchat` with attribute `jwtchat`
5) Creat an Edge Router Policy that gives the new identities access to your Edge Routers
6) Create a Service Edge Router Policy that allows `jwtchat` service usage on your Edge Routers
7) Create a Service Policy that allows your identities access to the `jwtchat` service
8) Add an External JWT Signer with a JWKS endpoint of `https://localhost:1280/keys`
9) Start the `jwtchat-idp` process
10) Start the `jwtchat-server`
11) Start the `jwtchat-client`