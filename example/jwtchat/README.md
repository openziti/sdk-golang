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

*Note: For Powershell ensure you escape pound (#) symbols with a grave tick (`)*

1) Stand up an OpenZiti network
2) Add an External JWT Signer with a JWKS endpoint
   1) `ziti edge create ext-jwt-signer jwtchat-idp "http://localhost:9998" -a openziti -u "http://localhost:9998/keys"`
   2) Save the resulting `ext-jwt-signer`
3) Create an authentication policy that allows the new `ext-jwt-signer` to authenticate identities
   1) `ziti edge create auth-policy jwtchat --primary-ext-jwt-allowed --primary-ext-jwt-allowed-signers<extjwtIdFromStep2>`
   2) Save the resulting `auth-policy` id
4) Create two identities (client, server)
   1) `ziti edge create identity service cid1 --external-id cid1 -a jwtchat -P <authPolicyIdFromStep3>`
   2) `ziti edge create identity service cid2 --external-id cid2 -a jwtchat -P <authPolicyIdFromStep3>`
5) Create at least one Edge Router
   1) `ziti edge create edge-router myRouter <myRouter.yml> -o myRouter.jwt`
   2) `ziti router enroll <myRouter.yml> -j myRouter.jwt`
6) Create a service named `jwtchat` with attribute `jwtchat`
   1) `ziti edge create service jwtchat -a jwtchat`
7) Creat an Edge Router Policy that gives the new identities access to your Edge Routers
   1) `ziti edge create edge-router-policy jwtchat --identity-roles #jwtchat --edge-router-roles #all`
8) Create a Service Edge Router Policy that allows `jwtchat` service usage on your Edge Routers
   1) `ziti edge create service-edge-router-policy jwtchat --service-roles #jwtchat --edge-router-roles #all`
9) Create a Service Policy that allows your identities access to the `jwtchat` service
   1) `ziti edge create service-policy jwtchat --service-roles #jwtchat --identity-roles #jwtchat`
10) Start the `jwtchat-idp` process
11) Start the `jwtchat-server` process
12) Start the `jwtchat-client` process