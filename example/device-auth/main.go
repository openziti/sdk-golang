package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/edge-api/rest_util"
	nfx509 "github.com/openziti/foundation/v2/x509"
	"github.com/openziti/sdk-golang/ziti"
	"gopkg.in/square/go-jose.v2/json"
)

func die[T interface{}](res T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return res
}

func main() {
	cfg := flag.String("config", "", "path to config file")
	openzitiURL := flag.String("ziti", "https://localhost:1280", "URL of the OpenZiti service")
	flag.Parse()

	var config *ziti.Config
	if cfg == nil || *cfg == "" {
		config = &ziti.Config{
			ZtAPI: *openzitiURL,
		}
		// warning: this call is insecure and should not be used in production
		ca := die(rest_util.GetControllerWellKnownCas(*openzitiURL))
		var buf bytes.Buffer
		_ = nfx509.MarshalToPem(ca, &buf)
		config.ID.CA = buf.String()
	} else {
		if openzitiURL == nil || *openzitiURL == "" {
			log.Fatal("OpenZiti URL must be specified")
		}
		config = die(ziti.NewConfigFromFile(*cfg))
	}
	ztx := die(ziti.NewContext(config))

	err := ztx.Authenticate()
	var provider *rest_model.ClientExternalJWTSignerDetail
	if err != nil {
		fmt.Println("Try authenticating with external provider")
		idps := die(ztx.GetExternalSigners())
		for idx, idp := range idps {
			fmt.Printf("%d: %s\n", idx, *idp.Name)
		}

		fmt.Printf("Select provider allowing device code flow.\nEnter number[0-%d] to authenticate: ", len(idps)-1)
		var id int
		_ = die(fmt.Scanf("%d", &id))

		provider = idps[id]
	}
	if provider == nil {
		log.Fatal("No provider found")
	}
	fmt.Printf("Using %s\n", *provider.Name)

	resp := die(http.Get(*provider.ExternalAuthURL + "/.well-known/openid-configuration"))
	var oidcConfig map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&oidcConfig)

	deviceAuth := oidcConfig["device_authorization_endpoint"].(string)
	scopes := append(provider.Scopes, "openid")
	ss := strings.Join(scopes, " ")
	resp = die(http.PostForm(deviceAuth, url.Values{
		"client_id": {*provider.ClientID},
		"scope":     {ss},
		"audience":  {*provider.Audience},
	}))

	var deviceCode map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&deviceCode)
	if completeUrl, ok := deviceCode["verification_uri_complete"]; ok {
		fmt.Printf("Open %s in your browser\n", completeUrl.(string))
	} else if verifyUrl, ok := deviceCode["verification_uri"]; ok {
		fmt.Printf("Open %s in your browser, and use code %s\n",
			verifyUrl.(string), deviceCode["user_code"].(string))
	} else {
		log.Fatal("Unable to determine verification URL")
	}

	interval := time.Duration(int(deviceCode["interval"].(float64))) * time.Second

	var token map[string]interface{}
	for {
		clear(token)
		time.Sleep(interval)

		tokenUrl := oidcConfig["token_endpoint"].(string)
		resp = die(http.PostForm(tokenUrl, url.Values{
			"client_id":   {*provider.ClientID},
			"device_code": {deviceCode["device_code"].(string)},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		}))

		json.NewDecoder(resp.Body).Decode(&token)
		errmsg, hasErr := token["error"]
		if !hasErr {
			break
		}
		errormsg := errmsg.(string)
		if errormsg == "authorization_pending" {
			fmt.Println("Waiting for user to authorize...")
			continue
		}
		log.Fatal(errormsg)
	}

	accessToken := token["access_token"].(string)
	tok, _ := jwt.Parse(accessToken, nil)
	if claims, ok := tok.Claims.(jwt.MapClaims); ok {
		for k, v := range claims {
			fmt.Printf("\t%s: %v\n", k, v)
		}
	}
	ztx.LoginWithJWT(accessToken)

	err = ztx.Authenticate()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Authenticated")

	services, _ := ztx.GetServices()
	fmt.Println("Available Services:")
	for _, svc := range services {
		fmt.Printf("\t%s\n", *svc.Name)
	}
}
