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
	"crypto/sha512"
	"encoding/json"
	"fmt"

	"github.com/cilium/cilium/pkg/labels"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sLbls "k8s.io/apimachinery/pkg/labels"
)

type RuleL4K8s struct {
	PodSelector metav1.LabelSelector `json:"coverage,omitempty"`
	Allow       []AllowL4            `json:"l4"`
}

func (l4 *RuleL4K8s) IsMergeable() bool {
	return true
}

func (l4 *RuleL4K8s) String() string {
	return fmt.Sprintf("Coverage: %s, Allows L4: %s", l4.PodSelector, l4.Allow)
}

func (l4 *RuleL4K8s) GetL4Policy(ctx *SearchContext, result *L4Policy) *L4Policy {
	fromBak := ctx.From
	ctx.From = removeRootK8sPrefixFromLabelArray(ctx.From)
	toBak := ctx.To
	ctx.To = removeRootK8sPrefixFromLabelArray(ctx.To)

	defer func() {
		ctx.From = fromBak
		ctx.To = toBak
	}()

	lbSelector, _ := metav1.LabelSelectorAsSelector(&l4.PodSelector)

	if !lbSelector.Matches(k8sLbls.Labels(ctx.To)) {
		policyTrace(ctx, "L4 Rule has no coverage: %s\n", l4)
		return nil
	}

	for _, a := range l4.Allow {
		a.Merge(result)
	}

	return result
}

func (l4 *RuleL4K8s) Resolve(node *Node) error {
	return nil
}

func (l4 *RuleL4K8s) SHA256Sum() (string, error) {
	sha := sha512.New512_256()
	if err := json.NewEncoder(sha).Encode(l4); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}

func (l4 *RuleL4K8s) CoverageSHA256Sum() (string, error) {
	lbSelector, _ := metav1.LabelSelectorAsSelector(&l4.PodSelector)
	if lbSelector.Empty() {
		return labels.LabelSliceSHA256Sum(nil)
	}
	l := labels.NewLabel("", "", "")
	l.Key = l4.PodSelector.String()
	return labels.LabelSliceSHA256Sum([]*labels.Label{l})
}
