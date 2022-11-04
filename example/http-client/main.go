package main

import (
	"context"
	"github.com/openziti/sdk-golang/ziti"
	"io"
	"net"
	"net/http"
	"os"
)

func newZitiClient() *http.Client {
	zitiTransport := http.DefaultTransport.(*http.Transport).Clone() // copy default transport
	zitiTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := ziti.NewDialerWithFallback(ctx, nil)
		return dialer.Dial(network, addr)
	}
	zitiTransport.TLSClientConfig.InsecureSkipVerify = true
	return &http.Client{Transport: zitiTransport}
}

// this is a clone of ../curlz but showing the use of ziti.Dialer
// identities are loaded from ZITI_IDENTITIES environment variable -- ';'-separated list of identity files
//
// saple usage:
// ```
//
//	$ export ZITI_IDENTITIES=<path to id file>
//	$ http-client http://<intercepted address>/path
//
// ```
func main() {
	resp, err := newZitiClient().Get(os.Args[1])
	if err != nil {
		panic(err)
	}

	_, err = io.Copy(os.Stdout, resp.Body)
	if err != nil {
		panic(err)
	}
}
