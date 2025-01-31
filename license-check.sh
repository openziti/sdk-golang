printf "Installing go-licenses"
go install github.com/google/go-licenses@latest

printf "\nGenerating license report"
$(go env GOPATH)/bin/go-licenses report ./... > /tmp/sdk.licenses

printf "\nGenerating set of unique licenses"
cat /tmp/sdk.licenses | cut -d ',' -f 3 | sort | uniq > /tmp/sdk.licenses.unique

printf "\nChecking Licenses\n"
diff expected.licenses /tmp/sdk.licenses.unique
