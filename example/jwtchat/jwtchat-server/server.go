package main

import (
	"bufio"
	"fmt"
	"github.com/Jeffail/gabs"
	"github.com/openziti/edge-api/rest_util"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/resty.v1"
	"os"
	"os/signal"
)

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	jwtToken, err := getExternalJWT()

	if err != nil {
		panic(err)
	}

	auth := rest_util.NewAuthenticatorAuthHeader("Bearer " + jwtToken)

	caPool, err := rest_util.GetControllerWellKnownCaPool("https://localhost:1280")

	if err != nil {
		panic(err)
	}

	cfg := &config.Config{
		ZtAPI:         "https://localhost:1280/edge/client/v1",
		Authenticator: auth,
		CaPool:        caPool,
	}
	ctx, err := ziti.NewContextWithConfig(cfg)

	if err != nil {
		panic(err)
	}

	err = ctx.Authenticate()

	if err != nil {
		panic(err)
	}

	svcs, err := ctx.GetServices()

	if err != nil {
		panic(err)
	}

	found := false
	for _, svc := range svcs {
		if *svc.Name == "jwtchat" {
			found = true
			break
		}
	}
	if !found {
		panic("jwtchat service not found")
	}

	listener, err := ctx.Listen("jwtchat")

	if err != nil {
		panic(err)
	}

	log.Println("listening for service: jwtchat")

	defer func() {
		_ = listener.Close()
	}()

	go func() {
		for {
			conn, err := listener.Accept()

			if err != nil {
				log.Errorf("error accepting connection: %s", err)
			}

			if listener.IsClosed() {
				return
			}

			go func() {
				byteBuffer := make([]byte, 128)

				for {
					n, err := conn.Read(byteBuffer)

					if err != nil {
						log.Errorf("error reading, exiting: %s", err)
						return
					}

					if n != 0 {
						fmt.Printf("client: %s", string(byteBuffer[0:n]))
					}
				}
			}()

			go func() {
				reader := bufio.NewReader(os.Stdin)
				for {
					fmt.Print("-> ")
					text, _ := reader.ReadString('\n')

					_, err := conn.Write([]byte(text))

					if err != nil {
						log.Errorf("error writing, exiting: %s", err)
						return
					}
				}
			}()

		}
	}()

	<-c

	return
}

// getExternalJWT will use Open ID Connect's client credentials flow to obtain a JWT from the jwtchat-idp executable.
func getExternalJWT() (string, error) {
	resp, err := resty.R().SetFormData(map[string]string{
		"client_secret": "cid2secret",
		"client_id":     "cid2",
		"grant_type":    "client_credentials",
		"scope":         "openid",
	}).Post("http://localhost:9998/oauth/token")

	if err != nil {
		return "", err
	}

	jsonContainer, err := gabs.ParseJSON(resp.Body())

	if err != nil {
		return "", err
	}

	if !jsonContainer.ExistsP("access_token") {
		return "", errors.New("no access_token property found")
	}

	token, ok := jsonContainer.Path("access_token").Data().(string)

	if !ok {
		return "", errors.New("access_token was not a valid JSON string")
	}

	return token, nil
}
