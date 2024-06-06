package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/Jeffail/gabs"
	edge_apis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/resty.v1"
	"os"
	"os/signal"
)

func main() {
	openzitiURL := flag.String("openziti-url", "https://localhost:1280", "URL of the OpenZiti service")
	idpTokenUrl := flag.String("idp-token-url", "http://localhost:9998/oauth/token", "URL of the Identity Provider")
	clientID := flag.String("client-id", "cid2", "Client ID for authentication")
	clientSecret := flag.String("client-secret", "cid2secret", "Client Secret for authentication")
	grantType := flag.String("grant-type", "client_credentials", "The grant type to use")
	scope := flag.String("scope", "openid", "The scope to use")

	// Parse flags
	flag.Parse()

	// Print values
	fmt.Println("OpenZiti URL\t:", *openzitiURL)
	fmt.Println("IDP URL\t\t:", *idpTokenUrl)
	fmt.Println("Client ID\t:", *clientID)
	fmt.Println("Client Secret\t:", *clientSecret)
	fmt.Println("Grant Type\t:", *grantType)
	fmt.Println("Scope\t\t:", *scope)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	jwtToken, err := getExternalJWT(*clientID, *clientSecret, *grantType, *scope, *idpTokenUrl)

	if err != nil {
		panic(err)
	}

	caPool, err := ziti.GetControllerWellKnownCaPool(*openzitiURL)

	if err != nil {
		panic(err)
	}

	authenticator := edge_apis.NewJwtCredentials(jwtToken)
	authenticator.CaPool = caPool

	cfg := &ziti.Config{
		ZtAPI: *openzitiURL + "/edge/client/v1",
		Credentials: authenticator,
	}
	ctx, err := ziti.NewContext(cfg)

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
func getExternalJWT(clientId string, clientSecret string, grantType string, scope string, idpTokenUrl string) (string, error) {
	resp, err := resty.R().SetFormData(map[string]string{
		"client_secret": clientSecret,
		"client_id":     clientId,
		"grant_type":    grantType,
		"scope":         scope,
	}).Post(idpTokenUrl)

	if err != nil {
		return "", err
	}
	json := resp.Body()
	jsonContainer, err := gabs.ParseJSON(json)

	if err != nil {
		return "", err
	}

	tokenName := "access_token"
	if !jsonContainer.ExistsP(tokenName) {
		return "", errors.New("no " + tokenName + " property found")
	}

	token, ok := jsonContainer.Path(tokenName).Data().(string)
	if !ok {
		return "", errors.New(tokenName + " was not a valid JSON string")
	}

	return token, nil
}
