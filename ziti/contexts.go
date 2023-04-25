/*
	Copyright 2019 NetFoundry Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

// Package ziti provides methods for loading Contexts which interact with an OpenZiti Controller via the Edge Client
// API to bind (host) services or dial (connect) to services.
//
// Each context is required to authenticate with the Edge Client API via Credentials instance. Credentials come in the
// form of identity files, username/password, JWTs, and more.
//
// Identity files specified in `ZITI_IDENTITIES` environment variable (semicolon separates) are loaded automatically
// at startup to populate the DefaultCollection. This behavior is deprecated, and explicit usage of an CtxCollection
// is suggested. This behavior can be replicated via NewSdkCollectionFromEnv().
package ziti

import (
	"github.com/openziti/edge-api/rest_model"
	edge_apis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/edge/posture"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/pkg/errors"
	"net/url"
	"strconv"
)

var idCount = 0

// NewId will return a unique string id suitable for ziti.Context Id functionality.
func NewId() string {
	idCount = idCount + 1

	return strconv.Itoa(idCount)
}

// NewContextFromFile attempts to load a new Config from the provided path and then uses that
// config to instantiate a new Context. See NewConfigFromFile() for configuration file details.
func NewContextFromFile(path string) (Context, error) {
	return NewContextFromFileWithOpts(path, nil)
}

// NewContextFromFileWithOpts does the same as NewContextFromFile but allow Options to be supplied.
func NewContextFromFileWithOpts(path string, options *Options) (Context, error) {
	cfg, err := NewConfigFromFile(path)

	if err != nil {
		return nil, err
	}

	return NewContextWithOpts(cfg, options)
}

// NewContext creates a Context from the supplied Config with the default options. See NewContextWithOpts().
func NewContext(cfg *Config) (Context, error) {
	return NewContextWithOpts(cfg, nil)
}

// NewContextWithOpts creates a Context from the supplied Config and Options. The configuration requires
// either the `ID` field or the `Credentials` field to be populated. If both are supplied, the `ID` field is used.
func NewContextWithOpts(cfg *Config, options *Options) (Context, error) {
	if options == nil {
		options = DefaultOptions
	}

	newContext := &ContextImpl{
		Id:                NewId(),
		routerConnections: cmap.New[edge.RouterConn](),
		options:           options,
		authQueryHandlers: map[string]func(query *rest_model.AuthQueryDetail, resp func(code string) error) error{},
		closeNotify:       make(chan struct{}),
	}

	if cfg == nil {
		return nil, errors.New("a config is required")
	}

	if cfg.ID.Cert != "" && cfg.ID.Key != "" {
		if cfg.Credentials != nil {
			idCreds := edge_apis.NewIdentityCredentialsFromConfig(cfg.ID)
			cfg.Credentials = edge_apis.NewSecondaryCredentials(idCreds, &cfg.Credentials)
		} else {
			cfg.Credentials = edge_apis.NewIdentityCredentialsFromConfig(cfg.ID)
		}
	} else if cfg.Credentials == nil {
		return nil, errors.New("either cfg.ID or cfg.Credentials must be provided")
	}

	apiUrl, err := url.Parse(cfg.ZtAPI)

	if err != nil {
		return nil, errors.Wrap(err, "could not parse ZtAPI from configuration as URI")
	}

	newContext.CtrlClt = &CtrlClient{
		ClientApiClient: edge_apis.NewClientApiClient(apiUrl, cfg.Credentials.GetCaPool()),
		Credentials:     cfg.Credentials,
		ConfigTypes:     cfg.ConfigTypes,
	}

	newContext.CtrlClt.PostureCache = posture.NewCache(newContext.CtrlClt, newContext.closeNotify)

	return newContext, nil
}
