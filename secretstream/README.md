# secretstream
Implementation of [libsodium](https://github.com/jedisct1/libsodium)'s [secretstream](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream) in Go

The main goal of this project is allow using `secretstream` between programs using libsodium and
programs written in Go without resorting to wrapping libsodium in Go. golang.org/x/crypto has all necessary
algorithms to make that happen.

Moved here from `github.com/openziti/secretstream` at v0.1.52, so that the crypto and the SDK
that depends on it can no longer be at different versions. It stays MIT licensed, which is why
this directory carries its own `LICENSE` alongside the repository's Apache 2.0 one.

## Testing against libsodium
It is important that this implementation is compatible with libsodium. Tests tagged with `compat_test` use libsodium to test compatibility.

make sure you have libsodium installed and ready to be used
```bash
$ sudo apt install libsodium libsodium-dev
```
_other platforms something similar_

You're ready to run tests!
```bash
$ go test --tags=compat_test ./...
```
