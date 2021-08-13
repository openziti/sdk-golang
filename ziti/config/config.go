/*
	Copyright 2019 NetFoundry, Inc.

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

package config

import (
	"github.com/michaelquigley/pfxlog"
	"encoding/json"
	"github.com/openziti/foundation/identity/identity"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
)

type Config struct {
	ZtAPI       string                  `json:"ztAPI"`
	ID          identity.IdentityConfig `json:"id"`
	ConfigTypes []string                `json:"configTypes"`
}

func New(ztApi string, idConfig identity.IdentityConfig) *Config {
	return &Config{
		ZtAPI: ztApi,
		ID:    idConfig,
	}
}

func NewFromFile(confFilePath string) (*Config, error) {
    // inspect config file inode
	pfxlog.Logger().Debugf("looking for config file (%s)", confFilePath)
	confFileInfo, err := os.Lstat(confFilePath)
	if err != nil {
		return nil, errors.Errorf("config file (%s) is not found ", confFilePath)
	}

	// if symlink then store resolved path
	var confFileResolved string
	if confFileInfo.Mode() & os.ModeSymlink != 0 {
		confFileResolved, err = os.Readlink(confFileInfo.Name())
		pfxlog.Logger().Debugf("config file (%s) is a symlink to %s", confFilePath, confFileResolved)
	} else {
		confFileResolved = confFileInfo.Name()
		pfxlog.Logger().Debugf("config file (%s) is a file", confFileResolved)
	}

	// read the JSON from resolved file path
	confJson, err := ioutil.ReadFile(confFileResolved)
	if err != nil {
		return nil, errors.Errorf("config file (%s) is not found ", confFileResolved)
	}

	// load JSON object
	c := Config{}
	err = json.Unmarshal(confJson, &c)
	if err != nil {
		return nil, errors.Errorf("failed to load ziti configuration (%s): %v", confFileResolved, err)
	}

	return &c, nil
}
