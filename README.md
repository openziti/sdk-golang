# Ziti SDK for Golang

Ziti is a modern, programmable network overlay with associated edge components, for application-embedded, zero trust network connectivity, written by developers for developers. Ziti allows developers to take control of networking while with secure connectivity and advanced security concepts such as Zero Trust.

This repository contains the Ziti SDK for `golang`.

# Enrollment
Prerequisite: Ziti Enrollment token in JWT format (e.g. `device.jwt`)

Run enrollment process to generate SDK configuration file -- `device.json`

```
$ ziti-enroller -jwt device.jwt -out device.json
```

Note: additional options (`-cert`, `-key`, `-engine`) 
are available to enroll with `ottCa` and `CA` methods

# Using SDK

SDK is using `ZITI_SDK_CONFIG` environment variable to load configuration file.
