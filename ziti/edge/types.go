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

package edge

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"
)

const (
	ClientConfigV1 = "ziti-tunneler-client.v1"
	InterceptV1    = "intercept.v1"
)

type CurrentIdentity struct {
	Id                        string                 `json:"id"`
	Name                      string                 `json:"name"`
	AppData                   map[string]interface{} `json:"appData"`
	DefaultHostingPrecedence  string                 `json:"defaultHostingPrecedence"`
	DefaultHostingCost        uint16                 `json:"defaultHostingCost"`
	ServiceHostingPrecedences map[string]interface{} `json:"serviceHostingPrecedences"`
	ServiceHostingCosts       map[string]interface{} `json:"serviceHostingCosts"`
}

type ApiIdentity struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type ApiSession struct {
	Id          string       `json:"id"`
	Token       string       `json:"token"`
	Identity    *ApiIdentity `json:"identity"`
	Expires     time.Time    `json:"expiresAt"`
	AuthQueries []*AuthQuery `json:"authQueries"`
}

type AuthQuery struct {
	Format     string `json:"format,omitempty"`
	HTTPMethod string `json:"httpMethod,omitempty"`
	HTTPURL    string `json:"httpUrl,omitempty"`
	MaxLength  int64  `json:"maxLength,omitempty"`
	MinLength  int64  `json:"minLength,omitempty"`
	Provider   string `json:"provider"`
}

type ServiceUpdates struct {
	LastChangeAt time.Time `json:"lastChangeAt"`
}

type EdgeRouter struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Urls     map[string]string
}

type SessionType string

const (
	SessionDial SessionType = "Dial"
	SessionBind SessionType = "Bind"
)

type Session struct {
	Id          string       `json:"id"`
	Service     ApiIdentity  `json:"service"`
	Token       string       `json:"token"`
	Type        SessionType  `json:"type"`
	EdgeRouters []EdgeRouter `json:"edgeRouters"`
}

type Service struct {
	Id             string                            `json:"id"`
	Name           string                            `json:"name"`
	Permissions    []string                          `json:"permissions"`
	Encryption     bool                              `json:"encryptionRequired"`
	PostureQueries []PostureQueries                  `json:"postureQueries"`
	Configs        map[string]map[string]interface{} `json:"config"`
	Tags           map[string]string                 `json:"tags"`
}

type Terminator struct {
	Id        string `json:"id"`
	ServiceId string `json:"serviceId"`
	RouterId  string `json:"routerId"`
	Identity  string `json:"Identity"`
}

type PostureQueries struct {
	IsPassing      bool `json:"isPassing"`
	PostureQueries []PostureQuery
}

type PostureQuery struct {
	Id        string               `json:"id"`
	IsPassing bool                 `json:"isPassing"`
	QueryType string               `json:"queryType"`
	Process   *PostureQueryProcess `json:"process"`
}

type PostureQueryProcess struct {
	OsType string `json:"osType"`
	Path   string `json:"path"`
}

func (service *Service) GetConfigOfType(configType string, target interface{}) (bool, error) {
	logger := pfxlog.Logger().WithField("serviceId", service.Id).WithField("serviceName", service.Name)
	if service.Configs == nil {
		logger.Debug("no service configs defined for service")
		return false, nil
	}
	configMap, found := service.Configs[configType]
	if !found {
		logger.Debugf("no service config of type %v defined for service", configType)
		return false, nil
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result: target,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.TextUnmarshallerHookFunc(),
			mapstructure.StringToTimeDurationHookFunc()),
	})

	if err != nil {
		logger.WithError(err).Debugf("unable to setup decoder for service configuration for type %v defined for service", configType)
		return true, errors.Wrap(err, "unable to setup decoder for service config structure")
	}

	if err := decoder.Decode(configMap); err != nil {
		logger.WithError(err).Debugf("unable to decode service configuration for type %v defined for service", configType)
		return true, errors.Wrap(err, "unable to decode service config structure")
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

type InteceptDialOptions struct {
	ConnectTimeoutSeconds *int
	Identity              *string
}

type PortRange struct {
	Low  uint16
	High uint16
}

type InterceptV1Config struct {
	Addresses   []ZitiAddress
	PortRanges  []*PortRange
	Protocols   []string
	SourceIp    *string
	DialOptions *InteceptDialOptions `json:"dialOptions"`
	Service     *Service
}

type DomainName string

func (dn DomainName) Match(hostname string) int {
	if len(dn) == 0 {
		return -1
	}

	if dn[0] == '*' {
		domain := string([]byte(dn)[1:])
		if strings.HasSuffix(hostname, domain) {
			return len(hostname) - len(domain)
		} else {
			return -1
		}
	} else {
		if hostname == string(dn) {
			return 0
		} else {
			return -1
		}
	}
}

func (pr *PortRange) Match(port uint16) int {
	if pr.Low <= port && port <= pr.High {
		return int(pr.High - pr.Low)
	}
	return -1
}

type ZitiAddress struct {
	cidr   *net.IPNet
	ip     net.IP
	domain DomainName
}

func (self *ZitiAddress) Matches(v any) int {
	if ip, ok := v.(net.IP); ok {
		if self.ip != nil {
			if ip.Equal(self.ip) {
				return 0
			} else {
				return -1
			}
		}

		if self.cidr != nil {
			if self.cidr.Contains(ip) {
				ones, bits := self.cidr.Mask.Size()
				return bits - ones
			} else {
				return -1
			}
		}
	} else if hostname, ok := v.(string); ok {
		return self.domain.Match(strings.ToLower(hostname))
	}

	return -1
}

func NewZitiAddress(str string) (*ZitiAddress, error) {
	addr := &ZitiAddress{}
	err := addr.UnmarshalText([]byte(str))
	if err != nil {
		return nil, err
	}
	return addr, nil
}

func (self *ZitiAddress) UnmarshalText(data []byte) error {
	v := string(data)
	if _, cidr, err := net.ParseCIDR(v); err == nil {
		self.cidr = cidr
		return nil
	}

	if ip := net.ParseIP(v); ip != nil {
		self.ip = ip
		return nil
	}

	// minimum valid hostname is `a.b`
	// minimum valid domain name is '*.c'
	if len(v) < 3 {
		return errors.New("invalid address")
	}

	if v[0] == '*' && v[1] != '.' {
		return errors.Errorf("invalid wildcard domain '%s'", v)
	}

	self.domain = DomainName(strings.ToLower(v))
	return nil
}

func (self *ZitiAddress) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	return self.UnmarshalText([]byte(v))
}

// Match returns the matching score of the given target address against this intercept
// returns -1 in case address is not matched
// if the address is matched returns a 32bit integer with upper bits set to hostname match and lower bits to port match
func (intercept *InterceptV1Config) Match(network, hostname string, port uint16) int {
	if !slices.Contains(intercept.Protocols, network) {
		return -1
	}

	var target any
	ip := net.ParseIP(hostname)
	if len(ip) != 0 {
		target = ip
	} else {
		target = hostname
	}

	addrScore := -1
	for _, address := range intercept.Addresses {
		score := address.Matches(target)
		if score == -1 {
			continue
		}

		if score == 0 {
			addrScore = 0
			break
		}

		if addrScore == -1 || score < addrScore {
			addrScore = score
		}
	}

	if addrScore == -1 {
		return -1
	}

	portScore := -1
	for _, portRange := range intercept.PortRanges {
		score := portRange.Match(port)
		if score == -1 {
			continue
		}

		if score == 0 {
			portScore = 0
			break
		}

		if portScore == -1 || score < portScore {
			portScore = score
		}
	}
	if portScore == -1 {
		return -1
	}

	return int(uint(addrScore)<<16 | (uint(portScore) & 0xFFFF))
}

type ClientConfig struct {
	Protocol string
	Hostname ZitiAddress
	Port     int
}

func (s *ClientConfig) String() string {
	return fmt.Sprintf("%v:%v:%v", s.Protocol, s.Hostname, s.Port)
}

func (self *ClientConfig) ToInterceptV1Config() *InterceptV1Config {

	return &InterceptV1Config{
		Protocols:  []string{"tcp", "udp"},
		Addresses:  []ZitiAddress{self.Hostname},
		PortRanges: []*PortRange{{Low: uint16(self.Port), High: uint16(self.Port)}},
	}
}
