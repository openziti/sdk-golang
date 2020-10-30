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
	"github.com/shirou/gopsutil/host"
	"regexp"
	"runtime"
	"strings"
)

type OsInfo struct {
	Type    string
	Version string
	Build   string
}

func Os() OsInfo {
	platform, family, version, _ := host.PlatformInformation()

	osType := "unknown"
	osVersion := "unknown"
	osBuild := "unknown"

	platform = strings.TrimSpace(strings.ToLower(platform))
	family = strings.TrimSpace(strings.ToLower(family))
	version = strings.TrimSpace(strings.ToLower(version))

	semVerParser := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)

	if runtime.GOOS == "windows" {
		osType = "windows"

		parsedVersion := semVerParser.FindStringSubmatch(version)

		if len(parsedVersion) > 1 {
			osVersion = parsedVersion[1]
		}

		if len(parsedVersion) > 3 {
			osBuild = parsedVersion[3]
		}
	} else if runtime.GOOS == "linux" {
		osType = "linux"

		kernel, _ := host.KernelVersion()

		parsedVersion := semVerParser.FindStringSubmatch(kernel)

		if len(parsedVersion) > 0 {
			osVersion = parsedVersion[0]
		}
	} else if runtime.GOOS == "darwin" {
		osType = "macOS"

		kernel, _ := host.KernelVersion()

		parsedVersion := semVerParser.FindStringSubmatch(kernel)

		if len(parsedVersion) > 0 {
			osVersion = parsedVersion[0]
		}
	} else {
		osType = runtime.GOOS
		kernel, _ := host.KernelVersion()
		osVersion = kernel
	}

	return OsInfo{
		Type:    osType,
		Version: osVersion,
		Build:   osBuild,
	}
}
