# Release notes 1.5.0

## Notes

Session and service refresh timers now include configurable jitter to avoid thundering-herd load spikes on the
controller. A new `RefreshJitter` field on `Options` controls the amount of randomization applied to refresh
intervals. It is a fraction (0.0–0.5) representing the ±percentage of the configured interval. The default
value is 0.1 (±10%), and the maximum allowed value is 0.5 (±50%).

For example, with the default 5-minute service refresh interval and 0.1 jitter, each refresh will fire at a
random time between 4m30s and 5m30s. Internally, fixed-interval tickers have been replaced with per-cycle
randomized timers, so each refresh cycle gets a newly randomized delay.

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.4.2 -> v1.5.0](https://github.com/openziti/sdk-golang/compare/v1.4.2...v1.5.0)
    * [Issue #832](https://github.com/openziti/sdk-golang/issues/832) - Fuzz session refresh timers
    * [Issue #879](https://github.com/openziti/sdk-golang/issues/879) - Return the connId in inspect response
    * [Issue #878](https://github.com/openziti/sdk-golang/issues/878) - Fix responses from rx goroutines
    * [Issue #874](https://github.com/openziti/sdk-golang/issues/874) - Add inspect support at the context level
    * [Issue #871](https://github.com/openziti/sdk-golang/issues/871) - Make SDK better at sticking to MaxTerminator terminators

* github.com/go-resty/resty/v2: v2.17.1 -> v2.17.2
* github.com/openziti/channel/v4: [v4.3.2 -> v4.3.6](https://github.com/openziti/channel/compare/v4.3.2...v4.3.6)
    * [Issue #228](https://github.com/openziti/channel/issues/228) - Ensure that Underlay never return nil on MultiChannel
    * [Issue #226](https://github.com/openziti/channel/issues/226) - Allow specifying a minimum number of underlays for a channel, regardless of underlay type

* github.com/openziti/edge-api: [v0.26.52 -> v0.26.56](https://github.com/openziti/edge-api/compare/v0.26.52...v0.26.56)
    * [Issue #170](https://github.com/openziti/edge-api/issues/170) - Add preferredLeader flag to controllers
    * [Issue #167](https://github.com/openziti/edge-api/issues/167) - Add ctrlChanListeners to router types

* github.com/openziti/foundation/v2: [v2.0.86 -> v2.0.87](https://github.com/openziti/foundation/compare/v2.0.86...v2.0.87)
* github.com/openziti/identity: [v1.0.124 -> v1.0.125](https://github.com/openziti/identity/compare/v1.0.124...v1.0.125)
* github.com/openziti/transport/v2: [v2.0.208 -> v2.0.209](https://github.com/openziti/transport/compare/v2.0.208...v2.0.209)

# Release notes 1.4.2

This release exposes internal OIDC responses for structures for testing purposes.

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.4.1 -> v1.4.2](https://github.com/openziti/sdk-golang/compare/v1.4.1...v1.4.2)

# Release notes 1.4.1

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.4.0 -> v1.4.1](https://github.com/openziti/sdk-golang/compare/v1.4.0...v1.4.1)
    * [Issue #860](https://github.com/openziti/sdk-golang/issues/860) - Make the dialing identity's id and name available on dialed connections

* github.com/openziti/channel/v4: [v4.2.50 -> v4.3.2](https://github.com/openziti/channel/compare/v4.2.50...v4.3.2)
    * [Issue #225](https://github.com/openziti/channel/issues/225) - Add ChannelCreated to the UnderlayHandler API to allow handlers to be initialized with the channel before binding
    * [Issue #224](https://github.com/openziti/channel/issues/224) - Update the underlay dispatcher to allow unknown underlay types to fall through to the default
    * [Issue #222](https://github.com/openziti/channel/issues/222) - Allow injecting the underlay type into messages

* github.com/openziti/foundation/v2: [v2.0.84 -> v2.0.86](https://github.com/openziti/foundation/compare/v2.0.84...v2.0.86)
* github.com/openziti/identity: [v1.0.122 -> v1.0.124](https://github.com/openziti/identity/compare/v1.0.122...v1.0.124)
* github.com/openziti/secretstream: [v0.1.46 -> v0.1.47](https://github.com/openziti/secretstream/compare/v0.1.46...v0.1.47)
* github.com/openziti/transport/v2: [v2.0.205 -> v2.0.208](https://github.com/openziti/transport/compare/v2.0.205...v2.0.208)
* github.com/zitadel/oidc/v3: v3.45.3 -> v3.45.4
* golang.org/x/oauth2: v0.34.0 -> v0.35.0
* golang.org/x/sys: v0.40.0 -> v0.41.0
* github.com/zitadel/logging: v0.6.2 -> v0.7.0
* go.opentelemetry.io/otel: v1.39.0 -> v1.40.0
* go.opentelemetry.io/otel/metric: v1.39.0 -> v1.40.0
* go.opentelemetry.io/otel/trace: v1.39.0 -> v1.40.0
* golang.org/x/crypto: v0.46.0 -> v0.47.0
* golang.org/x/net: v0.48.0 -> v0.49.0
* golang.org/x/term: v0.38.0 -> v0.40.0

# Release notes 1.4.0

## Notes

This release changes some of the internal apis, and some APIs which are primarily for testing/debugging, which is why the minor version is bumped. 
The externally facing APIs have not changed and router/controller compatibility is not affected.

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.3.1 -> v1.4.0](https://github.com/openziti/sdk-golang/compare/v1.3.1...v1.4.0)
    * [Issue #857](https://github.com/openziti/sdk-golang/issues/857) - Use new error code and retry hints to correctly react to terminator errors
    * [Issue #847](https://github.com/openziti/sdk-golang/issues/847) - Ensure the initial version check succeeds, to ensure we don't legacy sessions on ha or oidc-enabled controllers

* github.com/go-openapi/runtime: v0.29.0 -> v0.29.2
* github.com/go-openapi/strfmt: v0.24.0 -> v0.25.0
* github.com/go-resty/resty/v2: v2.16.5 -> v2.17.1
* github.com/golang-jwt/jwt/v5: v5.3.0 -> v5.3.1
* github.com/openziti/channel/v4: [v4.2.41 -> v4.2.50](https://github.com/openziti/channel/compare/v4.2.41...v4.2.50)
* github.com/openziti/edge-api: [v0.26.51 -> v0.26.52](https://github.com/openziti/edge-api/compare/v0.26.51...v0.26.52)
    * [Issue #164](https://github.com/openziti/edge-api/issues/164) - Add permissions list to identity

* github.com/openziti/foundation/v2: [v2.0.79 -> v2.0.84](https://github.com/openziti/foundation/compare/v2.0.79...v2.0.84)
    * [Issue #464](https://github.com/openziti/foundation/issues/464) - Add support for -pre in versions

* github.com/openziti/identity: [v1.0.118 -> v1.0.122](https://github.com/openziti/identity/compare/v1.0.118...v1.0.122)
* github.com/openziti/metrics: [v1.4.2 -> v1.4.3](https://github.com/openziti/metrics/compare/v1.4.2...v1.4.3)
    * [Issue #56](https://github.com/openziti/metrics/issues/56) - underlying resources of reference counted meters are not cleaned up when reference count hits zero

* github.com/openziti/secretstream: [v0.1.42 -> v0.1.46](https://github.com/openziti/secretstream/compare/v0.1.42...v0.1.46)
* github.com/openziti/transport/v2: [v2.0.198 -> v2.0.205](https://github.com/openziti/transport/compare/v2.0.198...v2.0.205)
* github.com/sirupsen/logrus: v1.9.3 -> v1.9.4
* github.com/zitadel/oidc/v3: v3.45.0 -> v3.45.3
* golang.org/x/oauth2: v0.31.0 -> v0.34.0
* golang.org/x/sys: v0.37.0 -> v0.40.0
* google.golang.org/protobuf: v1.36.10 -> v1.36.11
* github.com/cespare/xxhash/v2: v2.3.0 (new)
* github.com/go-openapi/analysis: v0.24.0 -> v0.24.1
* github.com/go-openapi/errors: v0.22.3 -> v0.22.4
* github.com/go-openapi/jsonreference: v0.21.2 -> v0.21.3
* github.com/go-openapi/loads: v0.23.1 -> v0.23.2
* github.com/go-openapi/spec: v0.22.0 -> v0.22.1
* github.com/go-openapi/validate: v0.25.0 -> v0.25.1
* github.com/zitadel/schema: v1.3.1 -> v1.3.2
* go.mongodb.org/mongo-driver: v1.17.4 -> v1.17.6
* go.opentelemetry.io/otel: v1.38.0 -> v1.39.0
* go.opentelemetry.io/otel/metric: v1.38.0 -> v1.39.0
* go.opentelemetry.io/otel/trace: v1.38.0 -> v1.39.0
* golang.org/x/crypto: v0.43.0 -> v0.46.0
* golang.org/x/net: v0.45.0 -> v0.48.0
* golang.org/x/sync: v0.17.0 -> v0.19.0
* golang.org/x/term: v0.36.0 -> v0.38.0
* golang.org/x/text: v0.30.0 -> v0.33.0


# Release notes 1.3.0

## What's New

* REST API ReEntry Support

## API Session Resumption

The OpenZiti Go SDK supports a `edge_apis` GoLang module. That module now supports API session resumption, enabling 
API Sessions to be (un)marshalled to storage between runs. Useful for API-driven development like CLIs where operation
is intemitent or over multiple application runs.

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: ReEntry Support

# Release notes 1.2.11

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.2.10 -> v1.2.11](https://github.com/openziti/sdk-golang/compare/v1.2.10...v1.2.11)
    * [Issue #824](https://github.com/openziti/sdk-golang/pull/824) - release notes and hard errors on no TOTP handler breaks partial auth events

* github.com/openziti/channel/v4: [v4.2.37 -> v4.2.41](https://github.com/openziti/channel/compare/v4.2.37...v4.2.41)
* github.com/openziti/edge-api: [v0.26.50 -> v0.26.51](https://github.com/openziti/edge-api/compare/v0.26.50...v0.26.51)
* github.com/openziti/foundation/v2: [v2.0.77 -> v2.0.79](https://github.com/openziti/foundation/compare/v2.0.77...v2.0.79)
* github.com/openziti/identity: [v1.0.116 -> v1.0.118](https://github.com/openziti/identity/compare/v1.0.116...v1.0.118)
* github.com/openziti/secretstream: [v0.1.39 -> v0.1.42](https://github.com/openziti/secretstream/compare/v0.1.39...v0.1.42)
* github.com/openziti/transport/v2: [v2.0.194 -> v2.0.198](https://github.com/openziti/transport/compare/v2.0.194...v2.0.198)
* golang.org/x/sys: v0.36.0 -> v0.37.0
* golang.org/x/crypto: v0.42.0 -> v0.43.0
* golang.org/x/net: v0.44.0 -> v0.45.0
* golang.org/x/term: v0.35.0 -> v0.36.0
* golang.org/x/text: v0.29.0 -> v0.30.0

# Release notes 1.2.10

## What's New

* HA Posture Check Support

## HA Posture Check Support

Upcoming releases of the OpenZiti controller and routers will support posture checks that are enforced at the router
level. This release adds support for that workflow when it is available.


## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.2.9 -> v1.2.10](https://github.com/openziti/sdk-golang/compare/v1.2.9...v1.2.10)

# Release notes 1.2.9

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.2.8 -> v1.2.9](https://github.com/openziti/sdk-golang/compare/v1.2.8...v1.2.9)
    * [Issue #818](https://github.com/openziti/sdk-golang/issues/818) - Full re-auth should not clear services list, as that breaks the on-change logic
    * [Issue #817](https://github.com/openziti/sdk-golang/issues/817) - goroutines can get stuck when iterating over randomized HA controller list

# Release notes 1.2.8

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.2.7 -> v1.2.8](https://github.com/openziti/sdk-golang/compare/v1.2.7...v1.2.8)
    * [Issue #736](https://github.com/openziti/sdk-golang/issues/736) - Migrate from github.com/mailru/easyjson
    * [Issue #807](https://github.com/openziti/sdk-golang/issues/807) - Don't send close from rxer to avoid blocking
    * [Issue #813](https://github.com/openziti/sdk-golang/issues/813) - SDK doesn't stop close listener when it detects that a service being hosted gets deleted

* github.com/go-openapi/runtime: v0.28.0 -> v0.29.0
* github.com/go-openapi/strfmt: v0.23.0 -> v0.24.0
* github.com/michaelquigley/pfxlog: v0.6.10 -> v1.0.0
* github.com/openziti/channel/v4: [v4.2.31 -> v4.2.37](https://github.com/openziti/channel/compare/v4.2.31...v4.2.37)
* github.com/openziti/edge-api: [v0.26.47 -> v0.26.48](https://github.com/openziti/edge-api/compare/v0.26.47...v0.26.48)
* github.com/openziti/foundation/v2: [v2.0.73 -> v2.0.77](https://github.com/openziti/foundation/compare/v2.0.73...v2.0.77)
    * [Issue #455](https://github.com/openziti/foundation/issues/455) - Correctly close goroutine pool when external close is signaled
    * [Issue #452](https://github.com/openziti/foundation/issues/452) - Goroutine pool with a min worker count of 1 can drop to 0 workers due to race condition

* github.com/openziti/identity: [v1.0.112 -> v1.0.116](https://github.com/openziti/identity/compare/v1.0.112...v1.0.116)
    * [Issue #68](https://github.com/openziti/identity/issues/68) - Shutdown file watcher when stopping identity watcher

* github.com/openziti/transport/v2: [v2.0.189 -> v2.0.194](https://github.com/openziti/transport/compare/v2.0.189...v2.0.194)
* github.com/zitadel/oidc/v3: v3.44.0 -> v3.45.0
* google.golang.org/protobuf: v1.36.9 -> v1.36.10
* github.com/go-openapi/analysis: v0.23.0 -> v0.24.0
* github.com/go-openapi/errors: v0.22.0 -> v0.22.3
* github.com/go-openapi/jsonpointer: v0.21.0 -> v0.22.1
* github.com/go-openapi/jsonreference: v0.21.0 -> v0.21.2
* github.com/go-openapi/loads: v0.22.0 -> v0.23.1
* github.com/go-openapi/spec: v0.21.0 -> v0.22.0
* github.com/go-openapi/swag: v0.23.0 -> v0.25.1
* github.com/go-openapi/swag/cmdutils: v0.25.1 (new)
* github.com/go-openapi/swag/conv: v0.25.1 (new)
* github.com/go-openapi/swag/fileutils: v0.25.1 (new)
* github.com/go-openapi/swag/jsonname: v0.25.1 (new)
* github.com/go-openapi/swag/jsonutils: v0.25.1 (new)
* github.com/go-openapi/swag/loading: v0.25.1 (new)
* github.com/go-openapi/swag/mangling: v0.25.1 (new)
* github.com/go-openapi/swag/netutils: v0.25.1 (new)
* github.com/go-openapi/swag/stringutils: v0.25.1 (new)
* github.com/go-openapi/swag/typeutils: v0.25.1 (new)
* github.com/go-openapi/swag/yamlutils: v0.25.1 (new)
* github.com/go-openapi/validate: v0.24.0 -> v0.25.0
* github.com/go-viper/mapstructure/v2: v2.4.0 (new)
* go.mongodb.org/mongo-driver: v1.17.0 -> v1.17.4
* go.opentelemetry.io/auto/sdk: v1.1.0 -> v1.2.1
* go.opentelemetry.io/otel: v1.37.0 -> v1.38.0
* go.opentelemetry.io/otel/metric: v1.37.0 -> v1.38.0
* go.opentelemetry.io/otel/trace: v1.37.0 -> v1.38.0
* go.yaml.in/yaml/v3: v3.0.4 (new)
* golang.org/x/crypto: v0.41.0 -> v0.42.0
* golang.org/x/net: v0.43.0 -> v0.44.0
* golang.org/x/sync: v0.16.0 -> v0.17.0
* golang.org/x/term: v0.34.0 -> v0.35.0
* golang.org/x/text: v0.28.0 -> v0.29.0

# Release notes 1.2.5

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.2.4 -> v1.2.5](https://github.com/openziti/sdk-golang/compare/v1.2.4...v1.2.5)
    * [Issue #804](https://github.com/openziti/sdk-golang/issues/804): Simplify OIDC flow for applications
    * [PR #797](https://github.com/openziti/sdk-golang/pull/797): Add.generic.msg.sink


# Release notes 1.2.4

## What's New

* Updates Go version to 1.24, in-line with Go's supported version policy
* Dependency updates and a minor logging fix

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.2.3 -> v1.2.4](https://github.com/openziti/sdk-golang/compare/v1.2.3...v1.2.4)
    * [Issue #800](https://github.com/openziti/sdk-golang/issues/800) - Tidy create service session logging

* github.com/openziti/channel/v4: [v4.2.21 -> v4.2.31](https://github.com/openziti/channel/compare/v4.2.21...v4.2.31)
* github.com/openziti/foundation/v2: [v2.0.70 -> v2.0.73](https://github.com/openziti/foundation/compare/v2.0.70...v2.0.73)
* github.com/openziti/identity: [v1.0.109 -> v1.0.112](https://github.com/openziti/identity/compare/v1.0.109...v1.0.112)
* github.com/openziti/secretstream: [v0.1.38 -> v0.1.39](https://github.com/openziti/secretstream/compare/v0.1.38...v0.1.39)
* github.com/openziti/transport/v2: [v2.0.183 -> v2.0.189](https://github.com/openziti/transport/compare/v2.0.183...v2.0.189)
* github.com/stretchr/testify: v1.10.0 -> v1.11.1
* golang.org/x/oauth2: v0.30.0 -> v0.31.0
* golang.org/x/sys: v0.35.0 -> v0.36.0
* google.golang.org/protobuf: v1.36.7 -> v1.36.9

# Release notes 1.2.3

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.2.2 -> v1.2.3](https://github.com/openziti/sdk-golang/compare/v1.2.2...v1.2.3)
    * [Issue #779](https://github.com/openziti/sdk-golang/issues/779) - Remove need to EnableHA flag in Go SDK

* github.com/openziti/channel/v4: [v4.2.19 -> v4.2.21](https://github.com/openziti/channel/compare/v4.2.19...v4.2.21)

# Release notes 1.2.2

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.2.1 -> v1.2.2](https://github.com/openziti/sdk-golang/compare/v1.2.1...v1.2.2)
    * [Issue #786](https://github.com/openziti/sdk-golang/issues/786) - Slow down dials to an ER if they happen too quickly
    * [Issue #784](https://github.com/openziti/sdk-golang/issues/784) - Drop retransmit error to debug

* github.com/golang-jwt/jwt/v5: v5.2.3 -> v5.3.0
* github.com/openziti/channel/v4: [v4.2.18 -> v4.2.19](https://github.com/openziti/channel/compare/v4.2.18...v4.2.19)
    * [Issue #203](https://github.com/openziti/channel/issues/203) - Track last dial time in UnderlayConstraints

* github.com/openziti/edge-api: [v0.26.46 -> v0.26.47](https://github.com/openziti/edge-api/compare/v0.26.46...v0.26.47)
* github.com/openziti/secretstream: [v0.1.37 -> v0.1.38](https://github.com/openziti/secretstream/compare/v0.1.37...v0.1.38)
* github.com/openziti/transport/v2: [v2.0.182 -> v2.0.183](https://github.com/openziti/transport/compare/v2.0.182...v2.0.183)
* github.com/rcrowley/go-metrics: v0.0.0-20201227073835-cf1acfcdf475 -> v0.0.0-20250401214520-65e299d6c5c9
* github.com/zitadel/oidc/v3: v3.42.0 -> v3.44.0
* golang.org/x/sys: v0.34.0 -> v0.35.0
* google.golang.org/protobuf: v1.36.6 -> v1.36.7
* github.com/fsnotify/fsnotify: v1.8.0 -> v1.9.0
* github.com/go-logr/logr: v1.4.2 -> v1.4.3
* go.opentelemetry.io/auto/sdk: v1.1.0 (new)
* go.opentelemetry.io/otel: v1.29.0 -> v1.37.0
* go.opentelemetry.io/otel/metric: v1.29.0 -> v1.37.0
* go.opentelemetry.io/otel/trace: v1.29.0 -> v1.37.0
* golang.org/x/crypto: v0.40.0 -> v0.41.0
* golang.org/x/net: v0.42.0 -> v0.43.0
* golang.org/x/term: v0.33.0 -> v0.34.0
* golang.org/x/text: v0.27.0 -> v0.28.0

# Release notes 1.2.1

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.2.0 -> v1.2.1](https://github.com/openziti/sdk-golang/compare/v1.2.0...v1.2.1)
    * [Issue #777](https://github.com/openziti/sdk-golang/issues/777) - OIDC auth token refresh doesn't fall back to re-auth if token has expired
    * [Issue #772](https://github.com/openziti/sdk-golang/issues/772) - xgress close tweaks
    * [Issue #769](https://github.com/openziti/sdk-golang/issues/769) - Require sdk flow control when using more than one default connection

* github.com/openziti/channel/v4: [v4.2.16 -> v4.2.18](https://github.com/openziti/channel/compare/v4.2.16...v4.2.18)
    * [Issue #201](https://github.com/openziti/channel/issues/201) - SendAndWait methods should return an error if the channel closes instead of blocking
    * [Issue #199](https://github.com/openziti/channel/issues/199) - Reject multi-underlay connections that are the first connection for a channel, but aren't marked as such.

# Release notes 1.2.0

## What's New

This release contains substantial revisions to the SDK flow control feature first released in v1.1.0.
See the v1.1.0 release notes for more details.

It has now received a substantial amount of testing including long running tests and backwards compability testing. 

These features should be used with version 1.6.6 or newer of OpenZiti.

It is still considered experimental, and the feature and APIs may still change, however Go SDK
users who are multi-plexing connections, are encouraged to try it out.

Once it has undergone sufficient soak time in a production environment, it will marked as stable.

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.1.2 -> v1.2.0](https://github.com/openziti/sdk-golang/compare/v1.1.2...v1.2.0)
    * [Issue #769](https://github.com/openziti/sdk-golang/issues/769) - Require sdk flow control when using more than one default connection
    * [Issue #765](https://github.com/openziti/sdk-golang/issues/765) - Allow independent close of xgress send and receive
    * [Issue #763](https://github.com/openziti/sdk-golang/issues/763) - Use a go-routine pool for payload ingest
    * [Issue #761](https://github.com/openziti/sdk-golang/issues/761) - Use cmap.ConcurrentMap for message multiplexer
    * [Issue #754](https://github.com/openziti/sdk-golang/issues/754) - panic: unaligned 64-bit atomic operation when running on 32-bit raspberry pi
    * [Issue #757](https://github.com/openziti/sdk-golang/issues/757) - Not authenticated check fails on session create when using OIDC

* github.com/golang-jwt/jwt/v5: v5.2.2 -> v5.2.3
* github.com/openziti/channel/v4: [v4.2.0 -> v4.2.15](https://github.com/openziti/channel/compare/v4.2.0...v4.2.15)
    * [Issue #194](https://github.com/openziti/channel/issues/194) - Add GetUnderlays and GetUnderlayCountsByType to Channel

* github.com/openziti/edge-api: [v0.26.45 -> v0.26.46](https://github.com/openziti/edge-api/compare/v0.26.45...v0.26.46)
    * [Issue #155](https://github.com/openziti/edge-api/issues/155) - Add network interface list to routers and identities

* github.com/openziti/foundation/v2: [v2.0.63 -> v2.0.70](https://github.com/openziti/foundation/compare/v2.0.63...v2.0.70)
    * [Issue #443](https://github.com/openziti/foundation/issues/443) - Allow injecting custom method into go-routine pools, to allow identifying them in stack dumps

* github.com/openziti/identity: [v1.0.101 -> v1.0.109](https://github.com/openziti/identity/compare/v1.0.101...v1.0.109)
* github.com/openziti/metrics: [v1.4.1 -> v1.4.2](https://github.com/openziti/metrics/compare/v1.4.1...v1.4.2)
* github.com/openziti/secretstream: [v0.1.34 -> v0.1.37](https://github.com/openziti/secretstream/compare/v0.1.34...v0.1.37)
* github.com/openziti/transport/v2: [v2.0.171 -> v2.0.182](https://github.com/openziti/transport/compare/v2.0.171...v2.0.182)
* github.com/zitadel/oidc/v3: v3.39.0 -> v3.41.0
* golang.org/x/sys: v0.33.0 -> v0.34.0
* golang.org/x/crypto: v0.38.0 -> v0.40.0
* golang.org/x/net: v0.40.0 -> v0.42.0
* golang.org/x/sync: v0.14.0 -> v0.16.0
* golang.org/x/term: v0.32.0 -> v0.33.0
* golang.org/x/text: v0.25.0 -> v0.27.0

# Release notes 1.1.2

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.1.1 -> v1.1.2](https://github.com/openziti/sdk-golang/compare/v1.1.1...v1.1.2)
    * [Issue #742](https://github.com/openziti/sdk-golang/issues/742) - Additional CtrlId and GetDestinationType for inspect support
    * [Issue #739](https://github.com/openziti/sdk-golang/issues/739) - go-jose v2.6.3 CVE-2025-27144 resolution

* github.com/zitadel/oidc/v3: v2.12.2 -> v3.39.0
* github.com/go-jose/go-jose/v4: v4.0.5 (new)
* github.com/zitadel/logging: v0.6.2 (new)
* github.com/zitadel/schema: v1.3.1 (new)

# Release notes 1.1.1

## Multi-underlay channel group secret

For additional security the experimental multi-underlay channel code now requires that 
clients provide a shared secret. This ensures that channels are get the expected 
underlays without requiring much larger group ids. This will require support on the
server side, so if the feature is enabled, router version 1.6.2+ will be required.

## Issues Fixed and Dependency Updates

# Release notes 1.1.1

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.1.0 -> v1.1.1](https://github.com/openziti/sdk-golang/compare/v1.1.0...v1.1.1)
    * [Issue #735](https://github.com/openziti/sdk-golang/issues/735) - Ensure Authenticate can't be called in parallel

* github.com/openziti/channel/v4: [v4.0.6 -> v4.1.3](https://github.com/openziti/channel/compare/v4.0.6...v4.1.3)
    * [Issue #187](https://github.com/openziti/channel/issues/187) - Allow fallback to regular channel when 'is grouped' isn't set when using multi-listener
    * [Issue #185](https://github.com/openziti/channel/issues/185) - Add group secret for multi-underlay channels

* github.com/openziti/edge-api: [v0.26.42 -> v0.26.45](https://github.com/openziti/edge-api/compare/v0.26.42...v0.26.45)
* github.com/openziti/foundation/v2: [v2.0.59 -> v2.0.63](https://github.com/openziti/foundation/compare/v2.0.59...v2.0.63)
* github.com/openziti/secretstream: [v0.1.32 -> v0.1.34](https://github.com/openziti/secretstream/compare/v0.1.32...v0.1.34)
* github.com/openziti/transport/v2: [v2.0.168 -> v2.0.171](https://github.com/openziti/transport/compare/v2.0.168...v2.0.171)
* golang.org/x/oauth2: v0.29.0 -> v0.30.0
* golang.org/x/sys: v0.32.0 -> v0.33.0
* golang.org/x/crypto: v0.36.0 -> v0.38.0
* golang.org/x/net: v0.38.0 -> v0.40.0
* golang.org/x/sync: v0.12.0 -> v0.14.0
* golang.org/x/term: v0.30.0 -> v0.32.0
* golang.org/x/text: v0.23.0 -> v0.25.0


# Release notes 1.1.0

## What's New

* Experimental support for sdk based flow-control
* Config change for multiple underlays

## SDK Flow Control

If the router being connected to supports it, the sdk can now manage flow control 
instead of delegating that to the router. This is mostly important when running
multiple simultaneous circuits throught the SDK. When running multiple circuits,
a slow circuit can get stalled at the router because of flow control back-pressure.
This then back-pressures all circuits from the SDK to that router. 

By moving the flow-control to the SDK, a slow circuit will not negatively impact
other circuits to the same router. This is currently enabled in the `DialOptions`
and `ListenOptions` for the dial and hosting sides respectively.

```
t := true
dialOptions := &ziti.DialOptions{
    ConnectTimeout: wf.ConnectTimeout,
    SdkFlowControl: &t,
}

listenOptions := ziti.DefaultListenOptions()
listenOptions.SdkFlowControl = &t
```

As this is an experimental feature, the configuration may change or be removed
in the future.

## Config Changes

The multi-underlay configuration has changed. There are now two settings.

```
// If set to a number greater than one, the sdk will attempt to create multiple connections to edge routers.
// This configuration value should not be considered part of the stable API yet. It currently defaults to one,
// but it may default to a larger number at some point in the future or be removed. If set to zero, it will
// be reset to one.
MaxDefaultConnections uint32 `json:"-"`

// If set to a number greater than zero, the sdk will attempt to create one or more separate connection to
// each edge routers for control plane data, such as dials. This configuration value should not be considered
// part of the stable API yet. It currently defaults to zero, but it may default to 1 at some point in the future
// or be removed.
MaxControlConnections uint32 `json:"-"`
```

The old `EnableSeparateControlPlaneConnection` setting is gone. Set `MaxControlConnections` to 1 to enable 
separation of control plane data.

Note that while present, the `MaxDefaultConnections` should not be used yet.

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.0.2 -> v1.1.0](https://github.com/openziti/sdk-golang/compare/v1.0.2...v1.1.0)
    * [Issue #702](https://github.com/openziti/sdk-golang/issues/702) - [Go SDK] Support xgress flow control from the SDK

* github.com/openziti/channel/v4: [v4.0.4 -> v4.0.6](https://github.com/openziti/channel/compare/v4.0.4...v4.0.6)
    * [Issue #182](https://github.com/openziti/channel/issues/182) - MultiListener can deadlock
    * [Issue #180](https://github.com/openziti/channel/issues/180) - Add GetUserData to Channel interface

* github.com/openziti/identity: [v1.0.100 -> v1.0.101](https://github.com/openziti/identity/compare/v1.0.100...v1.0.101)
    * [Issue #64](https://github.com/openziti/identity/issues/64) - Support a way to check if a cert/serverCert can be saved


# Release notes 1.0.2

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.0.1 -> v1.0.2](https://github.com/openziti/sdk-golang/compare/v1.0.1...v1.0.2)
  * [Issue #717](https://github.com/openziti/sdk-golang/issues/717) - ER connection race condition can leak connections
  * [Issue #689](https://github.com/openziti/sdk-golang/issues/689) - Concurrent map iteration and modification in getEdgeRouterConn causes panic

# Release notes 1.0.1

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v1.0.0 -> v1.0.1](https://github.com/openziti/sdk-golang/compare/v1.0.0...v1.0.1)
* github.com/openziti/channel/v4: [v4.0.3 -> v4.0.4](https://github.com/openziti/channel/compare/v4.0.3...v4.0.4)
* golang.org/x/oauth2: v0.28.0 -> v0.29.0
* golang.org/x/sys: v0.31.0 -> v0.32.0

# Release notes 1.0.0

## What's New

* Multi-connection support to edge routers
* Major version set to 1, to indicate compatibility with OpenZiti v1+

## Multi-connection support to edge router

If the `EnableSeparateControlPlaneConnection` is set to true in `ziti.Config`, 
the SDK will attempt to use a separate connection to each ER for control messaging.
If the router does not support this feature, then the SDK will fallback to using
a single connection.

Using a separate connection for control messaging will ensure that control messages
such as dials do not get stuck behind data messages. This is mostly important for
SDKs which are being used to host services or client side applications which are
multiplexing multiple connections, for example proxies and tunnelers.

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.25.2 -> v1.0.0](https://github.com/openziti/sdk-golang/compare/v0.25.2...v1.0.0)
    * [Issue #701](https://github.com/openziti/sdk-golang/issues/701) - Support multi-underlay channels for edge router connections

* github.com/openziti/channel/v4: [v4.0.1 -> v4.0.3](https://github.com/openziti/channel/compare/v4.0.1...v4.0.3)
    * [Issue #176](https://github.com/openziti/channel/issues/176) - Multi-channel need a mechanism to notify the txer that the underlay has closed

* github.com/openziti/metrics: [v1.3.0 -> v1.4.0](https://github.com/openziti/metrics/compare/v1.3.0...v1.4.0)
* github.com/openziti/transport/v2: [v2.0.167 -> v2.0.168](https://github.com/openziti/transport/compare/v2.0.167...v2.0.168)
* golang.org/x/net: v0.37.0 -> v0.38.0

# Release notes 0.25.2

## What's New

* Update to channel/v4
* Thank you to @Juneezee for contributing some libary tidying

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.25.1 -> v0.25.2](https://github.com/openziti/sdk-golang/compare/v0.25.1...v0.25.2)
* github.com/openziti/channel/v4: [v3.0.39 -> v4.0.1](https://github.com/openziti/channel/compare/v3.0.39...v4.0.1)
    * [Issue #172](https://github.com/openziti/channel/issues/172) - Support multi-underlay channels

# Release notes 0.25.0

## Go Version Update

The oldest supported Go version, as per the [Go Release Policy](https://go.dev/doc/devel/release#policy) 
is now 1.23. The OpenZiti Go SDK now requires Go v1.23.0 as its minimum version.

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.24.1 -> v0.25.0](https://github.com/openziti/sdk-golang/compare/v0.24.1...v0.25.0)
* github.com/go-resty/resty/v2: v2.16.4 -> v2.16.5
* github.com/openziti/channel/v3: [v3.0.27 -> v3.0.39](https://github.com/openziti/channel/compare/v3.0.27...v3.0.39)
    * [Issue #168](https://github.com/openziti/channel/issues/168) - Add DisconnectHandler to reconnecting channel

* github.com/openziti/edge-api: [v0.26.38 -> v0.26.42](https://github.com/openziti/edge-api/compare/v0.26.38...v0.26.42)
* github.com/openziti/foundation/v2: [v2.0.56 -> v2.0.59](https://github.com/openziti/foundation/compare/v2.0.56...v2.0.59)
* github.com/openziti/identity: [v1.0.94 -> v1.0.100](https://github.com/openziti/identity/compare/v1.0.94...v1.0.100)
* github.com/openziti/metrics: [v1.2.65 -> v1.3.0](https://github.com/openziti/metrics/compare/v1.2.65...v1.3.0)
    * [Issue #49](https://github.com/openziti/metrics/issues/49) - Make usage registry event queue size configurable
    * [Issue #50](https://github.com/openziti/metrics/issues/50) - Do metrics message construction in msg sender goroutine rather than usage/interval event goroutine

* github.com/openziti/secretstream: [v0.1.28 -> v0.1.32](https://github.com/openziti/secretstream/compare/v0.1.28...v0.1.32)
* github.com/openziti/transport/v2: [v2.0.160 -> v2.0.167](https://github.com/openziti/transport/compare/v2.0.160...v2.0.167)
* golang.org/x/oauth2: v0.25.0 -> v0.28.0
* golang.org/x/sys: v0.29.0 -> v0.31.0
* google.golang.org/protobuf: v1.36.3 -> v1.36.5
* github.com/fsnotify/fsnotify: v1.7.0 -> v1.8.0
* github.com/mattn/go-colorable: v0.1.13 -> v0.1.14
* golang.org/x/crypto: v0.32.0 -> v0.36.0
* golang.org/x/net: v0.34.0 -> v0.37.0
* golang.org/x/sync: v0.10.0 -> v0.12.0
* golang.org/x/term: v0.28.0 -> v0.30.0
* golang.org/x/text: v0.21.0 -> v0.23.0

# Release notes 0.24.1

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.24.0 -> v0.24.1](https://github.com/openziti/sdk-golang/compare/v0.24.0...v0.24.1)
    * [Issue #673](https://github.com/openziti/sdk-golang/issues/673) - Add license check to GH workflow

# Release notes 0.24.0

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.23.45 -> v0.24.0](https://github.com/openziti/sdk-golang/compare/v0.23.45...v0.24.0)
    * [Issue #663](https://github.com/openziti/sdk-golang/issues/663) - Add API to allow controlling proxying connections to controllers and routers.

* github.com/go-resty/resty/v2: v2.15.3 -> v2.16.4
* github.com/openziti/channel/v3: [v3.0.26 -> v3.0.27](https://github.com/openziti/channel/compare/v3.0.26...v3.0.27)
* github.com/openziti/edge-api: [v0.26.36 -> v0.26.38](https://github.com/openziti/edge-api/compare/v0.26.36...v0.26.38)
* github.com/openziti/transport/v2: [v2.0.159 -> v2.0.160](https://github.com/openziti/transport/compare/v2.0.159...v2.0.160)
* golang.org/x/oauth2: v0.23.0 -> v0.25.0
* google.golang.org/protobuf: v1.36.2 -> v1.36.3

# Release notes 0.23.45

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.23.44 -> v0.23.45](https://github.com/openziti/sdk-golang/compare/v0.23.44...v0.23.45)
    * [Issue #659](https://github.com/openziti/sdk-golang/issues/659) - E2E encryption can encounter ordering issues with high-volume concurrent writes

* github.com/openziti/channel/v3: [v3.0.4 -> v3.0.26](https://github.com/openziti/channel/compare/v3.0.4...v3.0.26)
    * [Issue #146](https://github.com/openziti/channel/issues/146) - Transport options aren't being set in dialer

* github.com/openziti/edge-api: [v0.26.34 -> v0.26.36](https://github.com/openziti/edge-api/compare/v0.26.34...v0.26.36)
    * [Issue #138](https://github.com/openziti/edge-api/issues/138) - management api deletes were generally not mapping 404 properly

* github.com/openziti/foundation/v2: [v2.0.49 -> v2.0.56](https://github.com/openziti/foundation/compare/v2.0.49...v2.0.56)
* github.com/openziti/identity: [v1.0.85 -> v1.0.94](https://github.com/openziti/identity/compare/v1.0.85...v1.0.94)

* github.com/openziti/metrics: [v1.2.58 -> v1.2.65](https://github.com/openziti/metrics/compare/v1.2.58...v1.2.65)
* github.com/openziti/secretstream: [v0.1.25 -> v0.1.28](https://github.com/openziti/secretstream/compare/v0.1.25...v0.1.28)
* github.com/openziti/transport/v2: [v2.0.146 -> v2.0.159](https://github.com/openziti/transport/compare/v2.0.146...v2.0.159)
* github.com/stretchr/testify: v1.9.0 -> v1.10.0
* golang.org/x/sys: v0.25.0 -> v0.29.0
* google.golang.org/protobuf: v1.34.2 -> v1.36.2
* golang.org/x/crypto: v0.27.0 -> v0.32.0
* golang.org/x/net: v0.29.0 -> v0.34.0
* golang.org/x/sync: v0.8.0 -> v0.10.0
* golang.org/x/term: v0.24.0 -> v0.28.0
* golang.org/x/text: v0.18.0 -> v0.21.0

# Release notes 0.23.44

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.23.43 -> v0.23.44](https://github.com/openziti/sdk-golang/compare/v0.23.43...v0.23.44)
* github.com/openziti/edge-api: [v0.26.32 -> v0.26.34](https://github.com/openziti/edge-api/compare/v0.26.32...v0.26.34)


# Release notes 0.23.43

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.23.42 -> v0.23.43](https://github.com/openziti/sdk-golang/compare/v0.23.42...v0.23.43)
    * [Issue #629](https://github.com/openziti/sdk-golang/issues/629) - JWT session refresh interprets expiration date incorrectly

* github.com/go-resty/resty/v2: v2.13.1 -> v2.15.3
* github.com/openziti/channel/v3: [v3.0.2 -> v3.0.4](https://github.com/openziti/channel/compare/v3.0.2...v3.0.4)
    * [Issue #144](https://github.com/openziti/channel/issues/144) - Add ReadAdapter utility

* github.com/openziti/edge-api: [v0.26.30 -> v0.26.32](https://github.com/openziti/edge-api/compare/v0.26.30...v0.26.32)
* github.com/openziti/secretstream: [v0.1.21 -> v0.1.25](https://github.com/openziti/secretstream/compare/v0.1.21...v0.1.25)
* go.mozilla.org/pkcs7: v0.0.0-20200128120323-432b2356ecb1 -> v0.9.0
* golang.org/x/oauth2: v0.21.0 -> v0.23.0
* go.mongodb.org/mongo-driver: v1.16.1 -> v1.17.0

# Release notes 0.23.42

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.23.41 -> v0.23.42](https://github.com/openziti/sdk-golang/compare/v0.23.41...v0.23.42)
  * [Issue #625](https://github.com/openziti/sdk-golang/issues/625) - traffic optimization: implement support for receiving multi-part edge payloads

# Release notes 0.23.41

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.23.40 -> v0.23.41](https://github.com/openziti/sdk-golang/compare/v0.23.40...v0.23.41)
* github.com/openziti/channel/v3: [v2.0.136 -> v3.0.2](https://github.com/openziti/channel/compare/v2.0.136...v3.0.2)
    * [Issue #138](https://github.com/openziti/channel/issues/138) - Allow custom message serialization. Add support for a 'raw' message type.
    * [Issue #82](https://github.com/openziti/channel/issues/82) - Remove transport.Configuration from UnderlayFactory.Create
    * [Issue #136](https://github.com/openziti/channel/issues/136) - Fix timeout on classic dialer 
    * [Issue #134](https://github.com/openziti/channel/issues/134) - Support the dtls transport

* github.com/openziti/edge-api: [v0.26.23 -> v0.26.30](https://github.com/openziti/edge-api/compare/v0.26.23...v0.26.30)
* github.com/openziti/foundation/v2: [v2.0.47 -> v2.0.49](https://github.com/openziti/foundation/compare/v2.0.47...v2.0.49)
* github.com/openziti/identity: [v1.0.81 -> v1.0.85](https://github.com/openziti/identity/compare/v1.0.81...v1.0.85)
* github.com/openziti/metrics: [v1.2.56 -> v1.2.58](https://github.com/openziti/metrics/compare/v1.2.56...v1.2.58)
* github.com/openziti/transport/v2: [v2.0.138 -> v2.0.146](https://github.com/openziti/transport/compare/v2.0.138...v2.0.146)
    * [Issue #92](https://github.com/openziti/transport/issues/92) - Implement simple traffic traffic
    * [Issue #85](https://github.com/openziti/transport/issues/85) - Update to latest dtls library

* github.com/zitadel/oidc/v2: v2.12.0 -> v2.12.2
* golang.org/x/sys: v0.22.0 -> v0.25.0
* github.com/gorilla/schema: v1.2.0 -> v1.3.0
* github.com/gorilla/securecookie: v1.1.1 -> v1.1.2
* github.com/gorilla/websocket: v1.5.1 -> v1.5.3
* go.mongodb.org/mongo-driver: v1.16.0 -> v1.16.1
* go.opentelemetry.io/otel: v1.28.0 -> v1.29.0
* go.opentelemetry.io/otel/metric: v1.28.0 -> v1.29.0
* go.opentelemetry.io/otel/trace: v1.28.0 -> v1.29.0
* golang.org/x/crypto: v0.25.0 -> v0.27.0
* golang.org/x/net: v0.27.0 -> v0.29.0
* golang.org/x/sync: v0.7.0 -> v0.8.0
* golang.org/x/term: v0.22.0 -> v0.24.0
* golang.org/x/text: v0.16.0 -> v0.18.0
* gopkg.in/go-jose/go-jose.v2: v2.6.3 (new)
* nhooyr.io/websocket: v1.8.11 -> v1.8.17

# Release notes 0.23.40

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.23.39 -> v0.23.40](https://github.com/openziti/sdk-golang/compare/v0.23.39...v0.23.40)
    * [Issue #601](https://github.com/openziti/sdk-golang/issues/601) - Only send config types on service list if controller version supports it
    * No Issue - Fixes a TOTP OIDC redirect

* github.com/openziti/edge-api: [v0.26.21 -> v0.26.23](https://github.com/openziti/edge-api/compare/v0.26.21...v0.26.23)
    * [Issue #120](https://github.com/openziti/edge-api/issues/120) - Add API for retrieving services referencing a config
    * [Issue #121](https://github.com/openziti/edge-api/issues/121) - Add API for retrieving the set of attribute roles used by posture checks

# Release notes 0.23.39

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.23.38 -> v0.23.39](https://github.com/openziti/sdk-golang/compare/v0.23.38...v0.23.39)
    * [Issue #596](https://github.com/openziti/sdk-golang/issues/596) - SDK should submit selected config types to auth and service list APIs
    * [Issue #593](https://github.com/openziti/sdk-golang/issues/593) - SDK Golang OIDC Get API Session Returns Wrong Value

* github.com/openziti/channel/v2: [v2.0.132 -> v2.0.136](https://github.com/openziti/channel/compare/v2.0.132...v2.0.136)
    * [Issue #132](https://github.com/openziti/channel/issues/132) - reconnecting dialer doesn't take local binding into account when reconnecting

* github.com/openziti/edge-api: [v0.26.20 -> v0.26.21](https://github.com/openziti/edge-api/compare/v0.26.20...v0.26.21)
* github.com/openziti/foundation/v2: [v2.0.46 -> v2.0.47](https://github.com/openziti/foundation/compare/v2.0.46...v2.0.47)
* github.com/openziti/identity: [v1.0.79 -> v1.0.81](https://github.com/openziti/identity/compare/v1.0.79...v1.0.81)
* github.com/openziti/metrics: [v1.2.55 -> v1.2.56](https://github.com/openziti/metrics/compare/v1.2.55...v1.2.56)
* github.com/openziti/secretstream: [v0.1.20 -> v0.1.21](https://github.com/openziti/secretstream/compare/v0.1.20...v0.1.21)
* github.com/openziti/transport/v2: [v2.0.135 -> v2.0.138](https://github.com/openziti/transport/compare/v2.0.135...v2.0.138)
    * [Issue #83](https://github.com/openziti/transport/issues/83) - tls.Dial should use proxy configuration if provided

* github.com/shirou/gopsutil/v3: v3.24.4 -> v3.24.5
* golang.org/x/oauth2: v0.20.0 -> v0.21.0
* golang.org/x/sys: v0.21.0 -> v0.22.0
* google.golang.org/protobuf: v1.34.1 -> v1.34.2
* go.mongodb.org/mongo-driver: v1.15.0 -> v1.16.0
* go.opentelemetry.io/otel: v1.27.0 -> v1.28.0
* go.opentelemetry.io/otel/metric: v1.27.0 -> v1.28.0
* go.opentelemetry.io/otel/trace: v1.27.0 -> v1.28.0
* golang.org/x/crypto: v0.24.0 -> v0.25.0
* golang.org/x/net: v0.26.0 -> v0.27.0
* golang.org/x/term: v0.21.0 -> v0.22.0

# Release notes 0.23.38

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.23.37 -> v0.23.38](https://github.com/openziti/sdk-golang/compare/v0.23.37...v0.23.38)
    * [Issue #573](https://github.com/openziti/sdk-golang/issues/573) - api session refresh spins in a tight loop if there is no current api session
    * [Issue #562](https://github.com/openziti/sdk-golang/issues/562) - Support sticky dials

* github.com/openziti/channel/v2: [v2.0.130 -> v2.0.132](https://github.com/openziti/channel/compare/v2.0.130...v2.0.132)
* github.com/openziti/edge-api: [v0.26.19 -> v0.26.20](https://github.com/openziti/edge-api/compare/v0.26.19...v0.26.20)
    * [Issue #113](https://github.com/openziti/edge-api/issues/113) - RecoveryCodesEnvelope is wrong

* github.com/openziti/foundation/v2: [v2.0.45 -> v2.0.46](https://github.com/openziti/foundation/compare/v2.0.45...v2.0.46)
    * [Issue #407](https://github.com/openziti/foundation/issues/407) - Remove Branch from build info

* github.com/openziti/identity: [v1.0.77 -> v1.0.79](https://github.com/openziti/identity/compare/v1.0.77...v1.0.79)
* github.com/openziti/metrics: [v1.2.54 -> v1.2.55](https://github.com/openziti/metrics/compare/v1.2.54...v1.2.55)
* github.com/openziti/transport/v2: [v2.0.133 -> v2.0.135](https://github.com/openziti/transport/compare/v2.0.133...v2.0.135)
* golang.org/x/sys: v0.20.0 -> v0.21.0
* github.com/go-logr/logr: v1.4.1 -> v1.4.2
* go.opentelemetry.io/otel: v1.25.0 -> v1.27.0
* go.opentelemetry.io/otel/metric: v1.25.0 -> v1.27.0
* go.opentelemetry.io/otel/trace: v1.25.0 -> v1.27.0
* golang.org/x/crypto: v0.23.0 -> v0.24.0
* golang.org/x/net: v0.25.0 -> v0.26.0
* golang.org/x/term: v0.20.0 -> v0.21.0
* golang.org/x/text: v0.15.0 -> v0.16.0


# Release notes 0.23.37

## Issues Fixed and Dependency Updates

* github.com/openziti/sdk-golang: [v0.23.36 -> v0.23.37](https://github.com/openziti/sdk-golang/compare/v0.23.36...v0.23.37)
    * [Issue #562](https://github.com/openziti/sdk-golang/issues/562) - Support sticky dials

* github.com/openziti/edge-api: [v0.26.18 -> v0.26.19](https://github.com/openziti/edge-api/compare/v0.26.18...v0.26.19)
* github.com/openziti/secretstream: [v0.1.19 -> v0.1.20](https://github.com/openziti/secretstream/compare/v0.1.19...v0.1.20)

# Release 0.23.12

* Fix DomainCheckRedirectPolicy for OIDC auth to controllers
* Update workflows
* Deps updates

# Release 0.23.11

## What's New

* Add GetCircuitId to edge.Conn. Allows correlation with controller/router metrics. Requires support from controller.

# Release 0.23.4

## What's New

* Adds `GetCurrentIdentityWithBackoff` so hosting doesn't fail on a single failure
* Ensure that ER dial requests time-out in a reasonable time frame
* Further refine edge session refreshes based on session changes and if we have hit the requested terminator count

# Release 0.23.2

## What's New

* `EnableHa` Feature Toggle

### `EnableHa` Feature Toggle

Configuration structs and files used to initialize SDK contexts now supports a boolean field named `EnableHa` (struct) 
and `enableHa` (JSON configuration) that enables OIDC HA authentication models. Existing implementations should not
have to make any adjustments as it will default to `false`/disabled. HA is experimental only and should not be used
unless one expects to test HA deployments.

# Release 0.23.0

## What's New

* `ApiSession` interface abstraction for HA support


### `ApiSession` Interface 
With the introduction of High Availability (HA) support, ApiSessions as a struct in `zitContext.Events()` callbacks
is no longer supported. A new `ApiSession` interface is provided in its place. This affects the following `Events()` functions:

  - `AddAuthenticationStatePartialListener`
  - `AddAuthenticationStateFullListener`
  - `AddAuthenticationStateUnauthenticatedListener`

This change is meant to alleviate issues between ApiSession fidelity between legacy and HA modes. However, it is
possible that information that was available with the struct version of `ApiSession` that is no longer available via
the interface value. As a short term work around, type casting the `ApiSession` interface to `ApiSessionLegacy` is
suggested. However, please provide feedback on scenarios where this is being done. It may be possible to enhance the
interface version if the data is available in both HA OIDC tokens and legacy ApiSession details.

The `ApiSession` interface supports the following functions:
- `GetAccessHeader() (string, string)` - returns the HTTP header name and value that should be used to represent this ApiSession
- `AuthenticateRequest(request runtime.ClientRequest, _ strfmt.Registry) error` - AuthenticateRequest fulfills the interface defined by OpenAPI libraries to authenticate client HTTP requests
- `GetToken() []byte` - returns the ApiSessions' token bytes 
- `GetExpiresAt() *time.Time` -  returns the time when the ApiSession will expire.
- `GetAuthQueries() rest_model.AuthQueryList` - returns a list of authentication queries the ApiSession is subjected to
- `GetIdentityName() string` - returns the name of the authenticating identity
- `GetIdentityId() string` - returns the id of the authenticating identity
- `GetId() string` - returns the id of the ApiSession

# Release 0.22.29

- Improve session refresh behavior. 

## Changes to API session refresh
* Limit refreshes of both api and sessions to at most every 30 seconds. 
* Base faster refreshes not on number of available ERs but on usable ER endpoints, since some ERs may not have usable endpoints
* Only refresh API sessions if session is no longer valid, as opposed if an api session refresh fails, which can happen if the 
  controller is down or busy.
* Only allow one api session refresh at a time
* Use exponential backoff for api session refresh retries

# Release 0.22.12

- Deprecate ListenOptions.MaxConnections in favor of ListenOptions.MaxTerminators

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

## What's New

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
