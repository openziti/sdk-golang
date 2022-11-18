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
	"reflect"
	"strings"
	"testing"
)

func TestNetworkSessionDecode(t *testing.T) {
	resp := `
{"meta":{},
"data":{"_links":{"self":{"href":"./sessions/a7dde565-dec8-4188-90e5-42f5d33bf5a6"}},
"edgeRouters":[
{"hostname":"hermes-host.ziti.netfoundry.io","name":"hermes","urls":{"tls":"tls://hermes-host.ziti.netfoundry.io:3022"}}],
"id":"a7dde565-dec8-4188-90e5-42f5d33bf5a6","token":"75d9aa68-dde3-4243-a062-50fab347b781"}}
`
	ns := new(Session)

	_, err := ApiResponseDecode(ns, strings.NewReader(resp))
	if err != nil {
		t.Fatal(err)
	}

	edgeRouters := make([]EdgeRouter, 1)
	edgeRouters[0].Name = "hermes"
	edgeRouters[0].Hostname = "hermes-host.ziti.netfoundry.io"
	edgeRouters[0].Urls = map[string]string{
		"tls": "tls://hermes-host.ziti.netfoundry.io:3022",
	}
	expected := &Session{
		Token:       "75d9aa68-dde3-4243-a062-50fab347b781",
		Id:          "a7dde565-dec8-4188-90e5-42f5d33bf5a6",
		EdgeRouters: edgeRouters,
	}

	if !reflect.DeepEqual(expected, ns) {
		t.Errorf("decode network session = %+v, want %+v", ns, expected)
	}
}

func TestInterceptDecode(t *testing.T) {
	str := `{
"protocols": ["tcp"],
"addresses": [
    "plain.host.ziti",
    "*.domain.ziti",
    "100.64.255.1",
    "100.64.0.0/10"
    ],
"portRanges": 
    [
      {"low": 80, "high": 80},
      {"low": 1024, "high": 2024}
    ]
}
`
	intercept := &InterceptV1Config{}

	err := json.Unmarshal([]byte(str), intercept)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		network  string
		hostname string
		port     uint16
	}
	cases := []struct {
		params   args
		expected int
	}{
		{params: args{network: "udp", hostname: "plain.host.ziti", port: 80}, expected: -1},
		{params: args{network: "tcp", hostname: "plain.host.ziti", port: 80}, expected: 0},
		{params: args{network: "tcp", hostname: "foo.domain.ziti", port: 80}, expected: int(3 << 16)},
		{params: args{network: "tcp", hostname: "foo.host.notziti", port: 80}, expected: -1},
		{params: args{network: "tcp", hostname: "bar.domain.ziti", port: 1024}, expected: int(3<<16 | 1000)},
		{params: args{network: "tcp", hostname: "100.64.255.1", port: 80}, expected: 0},
		{params: args{network: "tcp", hostname: "100.64.255.1", port: 1443}, expected: 1000},
		{params: args{network: "tcp", hostname: "100.64.0.1", port: 80}, expected: (32 - 10) << 16},
		{params: args{network: "tcp", hostname: "100.64.10.1", port: 1443}, expected: (32-10)<<16 | 1000},
	}

	for _, c := range cases {
		score := intercept.Match(c.params.network, c.params.hostname, c.params.port)
		if score != c.expected {
			t.Errorf("case[%s:%s:%d] => %x != %x", c.params.network,
				c.params.hostname, c.params.port, c.expected, score)
		}
	}
}
