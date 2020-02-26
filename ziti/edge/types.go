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

package edge

import (
	"encoding/json"
	"github.com/michaelquigley/pfxlog"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"io"
)

type ApiSession struct {
	Id    string `json:"id"`
	Token string `json:"token"`
	//Tags  []string `json:"tags"`
}

type EdgeRouter struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Urls     map[string]string
}

type Session struct {
	Id          string       `json:"id"`
	Token       string       `json:"token"`
	EdgeRouters []EdgeRouter `json:"edgeRouters"`
}

type Service struct {
	Id          string                            `json:"id"`
	Name        string                            `json:"name"`
	Permissions []string                          `json:"permissions"`
	Configs     map[string]map[string]interface{} `json:"config"`
	Tags        map[string]string                 `json:"tags"`
}

func (service *Service) GetConfigOfType(configType string, target interface{}) (bool, error) {
	if service.Configs == nil {
		pfxlog.Logger().Debugf("no service configs defined for service %v", service.Name)
		return false, nil
	}
	configMap, found := service.Configs[configType]
	if !found {
		pfxlog.Logger().Debugf("no service config of type %v defined for service %v", configType, service.Name)
		return false, nil
	}
	if err := mapstructure.Decode(configMap, target); err != nil {
		pfxlog.Logger().WithError(err).Debugf("unable to decode service configuration for of type %v defined for service %v", configType, service.Name)
		return true, errors.Errorf("unable to decode service config structure: %w", err)
	}
	return true, nil
}

type apiResponse struct {
	Data interface{}          `json:"data"`
	Meta *ApiResponseMetadata `json:"meta"`
}

type ApiResponseMetadata struct {
	FilterableFields []string `json:"filterableFields"`
	Pagination       *struct {
		Offset     int `json:"offset"`
		Limit      int `json:"limit"`
		TotalCount int `json:"totalCount"`
	} `json:"pagination"`
}

func ApiResponseDecode(data interface{}, resp io.Reader) (*ApiResponseMetadata, error) {
	apiR := &apiResponse{
		Data: data,
	}
	if err := json.NewDecoder(resp).Decode(apiR); err != nil {
		return nil, err
	}

	return apiR.Meta, nil
}
