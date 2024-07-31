# How to release the OpenZiti SDK for Go

As part of your PR, do the following:

* Make sure the buildinfo is up to date using:
    * `ziti-ci update-sdk-build-info`
    * This will update the version number in the code
* Make sure the release notes are up to date using: 
    * `ziti-ci build-sdk-release-notes`
    * This will emit the standard release notes to stdout. The release notes can be copied into the CHANGELOG.md and edited as necessary

Once your PR is merged and you wish to do a release:

1. Make sure you're on main and have the latest code
    1. `git checkout main`
    1. `git pull`
1. Tag the release
    1. `git tag -s <version number> -m "Release <version number>"`
    1. Push the tag: `git push origin <version number>`
