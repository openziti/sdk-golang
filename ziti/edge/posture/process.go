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
	"crypto/sha512"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/mitchellh/go-ps"
	"github.com/shirou/gopsutil/process"
	"io/ioutil"
)

type ProcessInfo struct {
	IsRunning          bool
	Hash               string
	SignerFingerprints []string
}

func Process(expectedPath string) ProcessInfo {
	processes, err := ps.Processes()

	if err != nil {
		fmt.Printf("error getting Processes: %v\n", err)
	}

	for _, proc := range processes {
		if !isProcessPath(expectedPath, proc.Executable()) {
			continue
		}

		procDetails, err := process.NewProcess(int32(proc.Pid()))

		if err != nil {
			continue
		}

		executablePath, err := procDetails.Exe()

		if err != nil {
			continue
		}

		if executablePath == expectedPath {
			isRunning, _ := procDetails.IsRunning()
			file, err := ioutil.ReadFile(executablePath)

			if err != nil {
				pfxlog.Logger().Warnf("could not read process executable file: %v", err)
				return ProcessInfo{
					IsRunning:          isRunning,
					Hash:               "",
					SignerFingerprints: nil,
				}
			}

			sum := sha512.Sum512(file)
			hash := fmt.Sprintf("%x", sum[:])

			signerFingerprints, err := getSignerFingerprints(executablePath)

			if err != nil {
				pfxlog.Logger().Warnf("could not read process signatures: %v", err)
				return ProcessInfo{
					IsRunning:          isRunning,
					Hash:               hash,
					SignerFingerprints: nil,
				}
			}

			return ProcessInfo{
				IsRunning:          isRunning,
				Hash:               hash,
				SignerFingerprints: signerFingerprints,
			}
		}
	}

	return ProcessInfo{
		IsRunning:          false,
		Hash:               "",
		SignerFingerprints: nil,
	}
}
