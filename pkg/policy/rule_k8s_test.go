// Copyright 2016-2017 Authors of Cilium
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

package policy

import (
	. "gopkg.in/check.v1"

	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (ds *PolicyTestSuite) TestK8sRule(c *C) {
	ctx := SearchContext{
		Trace: TRACE_VERBOSE,
		From: labels.LabelArray{
			labels.NewLabel("k8s.role", "frontend", k8sTypes.LabelSource),
		},
		To: labels.LabelArray{
			labels.NewLabel("root.k8s.role", "backend", k8sTypes.LabelSource),
		},
	}

	rule1 := &AllowRule{
		Action: api.ALWAYS_ACCEPT,
		Labels: labels.LabelArray{
			labels.NewLabel("k8s.role", "frontend", k8sTypes.LabelSource),
		},
	}

	k8sRule := RuleK8s{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"role": "backend",
			},
		},
		Allow: []Rule{rule1},
	}

	c.Assert(k8sRule.Allows(&ctx), Equals, api.ALWAYS_ACCEPT)
}

func (ds *PolicyTestSuite) TestremoveRootK8sPrefix(c *C) {
	var removeRootTests = []struct {
		input    string // input
		expected string // expected result
	}{
		{"", ""},
		{"root", ""},
		{"root.", ""},
		{"root.root.", "root."},
		{"root.root.k8s.", "root.k8s."},
		{"root.k8s.", ""},
		{"k8s.", ""},
		{"root.k8s.foo.bar", "foo.bar"},
	}
	for _, tt := range removeRootTests {
		actual := removeRootK8sPrefix(tt.input)
		c.Assert(actual, Equals, tt.expected)
	}
}
