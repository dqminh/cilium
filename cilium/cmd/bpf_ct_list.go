// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/ctmap"

	"github.com/spf13/cobra"
)

// bpfCtListCmd represents the bpf_ct_list command
var bpfCtListCmd = &cobra.Command{
	Use:    "list",
	Short:  "List connection tracking entries",
	PreRun: requireEndpointID,
	Run: func(cmd *cobra.Command, args []string) {
		dumpCtProto(ctmap.MapName6+args[0])
		dumpCtProto(ctmap.MapName4+args[0])
	},
}

func init() {
	bpfCtCmd.AddCommand(bpfCtListCmd)
}

func dumpCtProto(name string) {

	m, err := bpf.OpenMap(name)
	// TODO: fix dump :)
	out, err := m.Dump()
	if err != nil {
		Fatalf("Error while dumping BPF Map: %s\n", err)
	}

	fmt.Println(out)
}
