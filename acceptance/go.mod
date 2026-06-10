module github.com/openziti/sdk-golang/acceptance

go 1.25.0

require (
	github.com/stretchr/testify v1.11.1
	golang.org/x/mod v0.37.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
)

// The acceptance suite always tests the SDK in this tree, not a released module.
replace github.com/openziti/sdk-golang => ../
