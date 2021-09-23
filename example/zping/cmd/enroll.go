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
package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/openziti/sdk-golang/ziti/enroll"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func processEnrollment(jwtpath, outpath string) error {
	var keyAlg config.KeyAlgVar = "RSA"
	var keyPath, certPath, idname, caOverride string

	if strings.TrimSpace(outpath) == "" {
		out, outErr := outPathFromJwt(jwtpath)
		if outErr != nil {
			return fmt.Errorf("could not set the output path: %s", outErr)
		}
		outpath = out
	}

	if jwtpath != "" {
		if _, err := os.Stat(jwtpath); os.IsNotExist(err) {
			return fmt.Errorf("the provided jwt file does not exist: %s", jwtpath)
		}
	}

	if caOverride != "" {
		if _, err := os.Stat(caOverride); os.IsNotExist(err) {
			return fmt.Errorf("the provided ca file does not exist: %s", caOverride)
		}
	}

	if strings.TrimSpace(outpath) == strings.TrimSpace(jwtpath) {
		return fmt.Errorf("the output path must not be the same as the jwt path")
	}

	tokenStr, _ := ioutil.ReadFile(jwtpath)

	pfxlog.Logger().Debugf("jwt to parse: %s", tokenStr)
	tkn, _, err := enroll.ParseToken(string(tokenStr))

	if err != nil {
		return fmt.Errorf("failed to parse JWT: %s", err.Error())
	}

	flags := enroll.EnrollmentFlags{
		CertFile:      certPath,
		KeyFile:       keyPath,
		KeyAlg:        keyAlg,
		Token:         tkn,
		IDName:        idname,
		AdditionalCAs: caOverride,
	}

	conf, err := enroll.Enroll(flags)
	if err != nil {
		return fmt.Errorf("failed to enroll: %v", err)
	}

	output, err := os.Create(outpath)
	if err != nil {
		return fmt.Errorf("failed to open file '%s': %s", outpath, err.Error())
	}
	defer func() { _ = output.Close() }()

	enc := json.NewEncoder(output)
	enc.SetEscapeHTML(false)
	encErr := enc.Encode(&conf)

	if encErr == nil {
		pfxlog.Logger().Infof("enrolled successfully. identity file written to: %s", outpath)
		return nil
	} else {
		return fmt.Errorf("enrollment successful but the identity file was not able to be written to: %s [%s]", outpath, encErr)
	}
}

func outPathFromJwt(jwt string) (string, error) {
	outFlag := "out"
	if strings.HasSuffix(jwt, ".jwt") {
		return jwt[:len(jwt)-len(".jwt")] + ".json", nil
	} else if strings.HasSuffix(jwt, ".json") {
		//ugh - so that makes things a bit uglier but ok fine. we'll return an error in this situation
		return "", errors.Errorf("unexpected configuration. cannot infer '%s' flag if the jwt file "+
			"ends in .json. rename jwt file or provide the '%s' flag", outFlag, outFlag)
	} else {
		//doesn't end with .jwt - so just slap a .json on the end and call it a day
		return jwt + ".json", nil
	}
}

// enrollCmd represents the enroll command
var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll an identity",
	Long:  `This command enrolls an identity with an input jwt file and outputs a json identity file.`,
	Run: func(cmd *cobra.Command, args []string) {
		jflag, _ := cmd.Flags().GetString("jwt")
		oflag, _ := cmd.Flags().GetString("out")

		if len(jflag) > 0 {
			err := processEnrollment(jflag, oflag)
			if err != nil {
				logrus.WithError(err).Error("Error enrolling")
				os.Exit(1)
			}
			os.Exit(0)
		} else {
			fmt.Fprintf(os.Stderr, "'enroll command' requires -j,--jwt <jwt file path>\n")
			os.Exit(2)
		}

	},
}

func init() {
	rootCmd.AddCommand(enrollCmd)
	enrollCmd.Flags().StringP("jwt", "j", "", "Name/Location of jwt file")
	enrollCmd.Flags().StringP("out", "o", "", "Optional: Name/Location of output identity file")
}
