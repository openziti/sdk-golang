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

package posture

import (
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/edge/api"
	cmap "github.com/orcaman/concurrent-map"
	"sync"
	"time"
)

type Cache struct {
	processes       cmap.ConcurrentMap // map[processPath]ProcessInfo
	MacAddresses    []string
	Os              OsInfo
	Domain          string
	serviceQueryMap map[string]map[string]edge.PostureQuery
	activeServices  cmap.ConcurrentMap // map[serviceId]

	lastSent   cmap.ConcurrentMap //map[type|processQueryid]time.Time
	timeout    time.Duration
	ctrlClient api.Client

	startOnce sync.Once
}

func NewCache(ctrlClient api.Client) *Cache {
	cache := &Cache{
		processes:    cmap.New(),
		MacAddresses: []string{},
		Os: OsInfo{
			Type:    "",
			Version: "",
			Build:   "",
		},
		Domain:          "",
		serviceQueryMap: map[string]map[string]edge.PostureQuery{},
		activeServices:  cmap.New(),
		lastSent:        cmap.New(),
		timeout:         20 * time.Second,
		ctrlClient:      ctrlClient,
		startOnce:       sync.Once{},
	}
	cache.start()

	return cache
}

func (cache *Cache) setProcesses(processPaths []string) {

	processMap := map[string]struct{}{}

	for _, processPath := range processPaths {
		processMap[processPath] = struct{}{}
	}

	var processesToRemove []string
	cache.processes.IterCb(func(processPath string, _ interface{}) {
		if _, ok := processMap[processPath]; !ok {
			processesToRemove = append(processesToRemove, processPath)
		}
	})

	for _, processPath := range processesToRemove {
		cache.processes.Remove(processPath)
	}

	for processPath := range processMap {
		cache.processes.Upsert(processPath, nil, func(exist bool, valueInMap interface{}, newValue interface{}) interface{} {
			if !exist {
				return Process(processPath)
			}
			return valueInMap
		})
	}
}

func (cache *Cache) ProcessInfo(processPath string) ProcessInfo {
	if val, found := cache.processes.Get(processPath); found {
		return val.(ProcessInfo)
	} else {
		return ProcessInfo{
			IsRunning:          false,
			Hash:               "",
			SignerFingerprints: nil,
		}
	}
}

func (cache *Cache) Refresh() {
	for _, processPath := range cache.processes.Keys() {
		cache.processes.Set(processPath, Process(processPath))
	}

	cache.MacAddresses = MacAddresses()
	cache.Os = Os()
	cache.Domain = Domain()
}

func (cache *Cache) SetServiceQueryMap(serviceQueryMap map[string]map[string]edge.PostureQuery) {
	cache.serviceQueryMap = serviceQueryMap

	var processPaths []string
	for _, queryMap := range serviceQueryMap {
		for _, query := range queryMap {
			if query.QueryType == "PROCESS" && query.Process != nil {
				processPaths = append(processPaths, query.Process.Path)
			}
		}
	}

	cache.setProcesses(processPaths)
}

func (cache *Cache) AddActiveService(serviceId string) {
	cache.activeServices.Set(serviceId, struct{}{})
	cache.sendResponsesForService(serviceId)
}

func (cache *Cache) RemoveService(serviceId string) {
	cache.activeServices.Remove(serviceId)
}

func (cache *Cache) sendResponsesForService(serviceId string) {
	cache.Refresh()
	if queryMap, ok := cache.serviceQueryMap[serviceId]; ok {
		for _, query := range queryMap {
			cache.sendResponse(query)
		}
	}
}

func (cache *Cache) start() {
	cache.startOnce.Do(func() {
		ticker := time.NewTicker(5 * time.Second)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					pfxlog.Logger().Errorf("error during posture response streaming: %v", r)
				}
			}()

			for _ = range ticker.C {
				cache.Refresh()
				var serviceIds []string
				cache.activeServices.IterCb(func(serviceId string, _ interface{}) {
					serviceIds = append(serviceIds, serviceId)
				})

 				for _, serviceId := range serviceIds {
					cache.sendResponsesForService(serviceId)
				}
			}
		}()
	})
}

func (cache *Cache) sendResponse(query edge.PostureQuery) {
	key := query.QueryType

	if query.QueryType == "PROCESS" {
		key = query.Id
	}

	if key != "" {
		mustSend := false
		if val, found := cache.lastSent.Get(key); !found {
			mustSend = true
		} else {
			lastSent, _ := val.(time.Time)
			mustSend = lastSent.Add(cache.timeout).After(time.Now())
		}

		if mustSend {
			cache.lastSent.Set(key, time.Now())
			response := api.PostureResponse{
				Id:     query.Id,
				TypeId: query.QueryType,
			}

			switch query.QueryType {
			case "MAC":
				response.PostureSubType = api.PostureResponseMac{
					MacAddresses: cache.MacAddresses,
				}
			case "OS":
				response.PostureSubType = api.PostureResponseOs{
					Type:    cache.Os.Type,
					Version: cache.Os.Version,
					Build:   cache.Os.Build,
				}
			case "PROCESS":
				if query.Process != nil {
					process := cache.ProcessInfo(query.Process.Path)

					postureSubType := api.PostureResponseProcess{
						IsRunning: process.IsRunning,
						Hash:      process.Hash,
					}

					if len(process.SignerFingerprints) > 0 {
						postureSubType.SignerFingerprint = process.SignerFingerprints[0]
					}

					response.PostureSubType = postureSubType
				}

			case "DOMAIN":
				response.PostureSubType = api.PostureResponseDomain{
					Domain: cache.Domain,
				}
			}

			if err := cache.ctrlClient.SendPostureResponse(response); err != nil {
				pfxlog.Logger().Error(err)
			}
		}
	}
}
