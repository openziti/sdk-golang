package api

import (
	"fmt"
	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"net/url"
	"os"
	"sync"
)

func NewLazyClient(config *config.Config, initCallback func(Client) error) Client {
	return &lazyClient{
		config:       config,
		initComplete: initCallback,
	}
}

type lazyClient struct {
	RestClient
	config       *config.Config
	initDone     sync.Once
	initComplete func(Client) error
	id           identity.Identity

	authToken string
}

func (client *lazyClient) GetIdentity() identity.Identity {
	return client.id
}

func (client *lazyClient) SetAuthToken(token string) {
	if client.RestClient != nil {
		client.RestClient.SetAuthToken(token)
	}

	client.authToken = token
}

func (client *lazyClient) GetAuthToken() string {
	if client.RestClient != nil {
		return client.RestClient.GetAuthToken()
	}

	return client.authToken
}

func (client *lazyClient) ensureConfigPresent() error {
	if client.config != nil {
		return nil
	}

	const configEnvVarName = "ZITI_SDK_CONFIG"
	// If configEnvVarName is set, try to use it.
	// The calling application may override this by calling NewContextWithConfig
	confFile := os.Getenv(configEnvVarName)

	if confFile == "" {
		return errors.Errorf("unable to configure ziti as config environment variable %v not populated", configEnvVarName)
	}

	logrus.Infof("loading Ziti configuration from %s", confFile)
	cfg, err := config.NewFromFile(confFile)
	if err != nil {
		return errors.Errorf("error loading config file specified by ${%s}: %v", configEnvVarName, err)
	}
	client.config = cfg
	return nil
}

func (client *lazyClient) Initialize() error {
	var err error
	client.initDone.Do(func() {
		err = client.load()
	})
	return err
}

func (client *lazyClient) load() error {
	err := client.ensureConfigPresent()
	if err != nil {
		return err
	}

	zitiUrl, err := url.Parse(client.config.ZtAPI)

	if err != nil {
		return fmt.Errorf("could not parse Ziti API URL: %v", err)
	}

	client.id, err = identity.LoadIdentity(client.config.ID)
	if err != nil {
		return err
	}
	client.RestClient, err = NewClient(zitiUrl, client.id.ClientTLSConfig(), client.config.ConfigTypes)

	if err != nil {
		return err
	}

	if client.authToken != "" {
		client.SetAuthToken(client.authToken)
	}
	return client.initComplete(client)
}
