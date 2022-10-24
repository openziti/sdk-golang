/*
	Copyright NetFoundry Inc.

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

package main

import (
	_ "embed"
	"github.com/openziti/runzmd"
	"github.com/openziti/runzmd/actionz"
	"github.com/spf13/cobra"
	"time"
)

//go:embed setup.md
var scriptSource []byte

type setupAction struct {
	ControllerUrl string
	Username      string
	Password      string
	NewlinePause  time.Duration
	AssumeDefault bool
	interactive   bool
}

func (self *setupAction) GetControllerUrl() string {
	return self.ControllerUrl
}

func (self *setupAction) GetUsername() string {
	return self.Username
}

func (self *setupAction) GetPassword() string {
	return self.Password
}

func newSetupCmd() *cobra.Command {
	action := &setupAction{}

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Walks you through configuration for the sdk-golang chat-p2p example",
		Args:  cobra.ExactArgs(0),
		RunE:  action.run,
	}

	// allow interspersing positional args and flags
	cmd.Flags().SetInterspersed(true)
	cmd.Flags().StringVar(&action.ControllerUrl, "controller-url", "", "The Ziti controller URL to use")
	cmd.Flags().StringVarP(&action.Username, "username", "u", "", "The Ziti controller username to use")
	cmd.Flags().StringVarP(&action.Password, "password", "p", "", "The Ziti controller password to use")
	cmd.Flags().DurationVar(&action.NewlinePause, "newline-pause", time.Millisecond*10, "How long to pause between lines when scrolling")
	cmd.Flags().BoolVar(&action.interactive, "interactive", false, "Interactive mode, waiting for user input")

	return cmd
}

func (self *setupAction) run(*cobra.Command, []string) error {
	t := runzmd.NewRunner()
	t.NewLinePause = self.NewlinePause
	t.AssumeDefault = !self.interactive

	t.RegisterActionHandler("ziti", &actionz.ZitiRunnerAction{})
	t.RegisterActionHandler("ziti-login", &actionz.ZitiEnsureLoggedIn{
		LoginParams: self,
	})
	t.RegisterActionHandler("keep-session-alive", &actionz.KeepSessionAliveAction{})

	return t.Run(scriptSource)
}
