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
	"strings"

	"github.com/cilium/cilium/common"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sLbls "k8s.io/apimachinery/pkg/labels"
)

type K8sSelector struct {
	PodSelector       *metav1.LabelSelector `json:"podSelector,omitempty"`
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

func (s K8sSelector) String() string {
	if s.PodSelector != nil {
		return fmt.Sprintf("{pod: %s}", s.PodSelector.String())
	} else if s.NamespaceSelector != nil {
		return fmt.Sprintf("{namespace: %s}", s.NamespaceSelector.String())
	}
	return "nil"
}

type K8sAllowRule struct {
	Action   api.ConsumableDecision `json:"action,omitempty"`
	Selector K8sSelector            `json:"selector"`
}

func (a *K8sAllowRule) IsMergeable() bool {
	switch a.Action {
	case api.DENY:
		// Deny rules will result in immediate return from the policy
		// evaluation process and thus rely on strict ordering of the rules.
		// Merging of such rules in a node will result in undefined behaviour.
		return false
	}

	return true
}

func (a *K8sAllowRule) String() string {
	return fmt.Sprintf("{selector: %s, action: %s}", a.Selector, a.Action.String())
}

func (a *K8sAllowRule) Allows(ctx *SearchContext) api.ConsumableDecision {
	ctx.Depth++
	defer func() {
		ctx.Depth--
	}()

	if a.Selector.PodSelector != nil {
		lbSelector, _ := metav1.LabelSelectorAsSelector(a.Selector.PodSelector)
		if lbSelector.Matches(k8sLbls.Labels(ctx.From)) {
			return a.Action
		}
	} else if a.Selector.NamespaceSelector != nil {
		lbSelector, _ := metav1.LabelSelectorAsSelector(a.Selector.NamespaceSelector)
		if lbSelector.Matches(k8sLbls.Labels(ctx.From)) {
			return a.Action
		}
	}

	return api.UNDECIDED
}

// RuleK8s allows the following consumers.
type RuleK8s struct {
	PodSelector metav1.LabelSelector `json:"coverage,omitempty"`
	Allow       []Rule               `json:"allow"`
}

func (prc *RuleK8s) IsMergeable() bool {
	for _, r := range prc.Allow {
		if !r.IsMergeable() {
			return false
		}
	}

	return true
}

func (prc *RuleK8s) String() string {
	var coverage string
	allows := []string{}
	for _, allow := range prc.Allow {
		allows = append(allows, allow.String())
	}
	lbSelector, _ := metav1.LabelSelectorAsSelector(&prc.PodSelector)
	if lbSelector.Empty() {
		all := labels.NewLabel(labels.IDNameAll, "", common.ReservedLabelSource)
		coverage = all.String()
	} else {
		coverage = prc.PodSelector.String()
	}
	return fmt.Sprintf("Coverage: [%s] Allowing: [%s]", coverage,
		strings.Join(allows, " "))
}

// removeRootK8sPrefix removes an eventual `root.`, `root`, `k8s`, `k8s.`,
// `root.k8s.`, `root.k8s` prefix from the path.
func removeRootK8sPrefix(path string) string {
	path = removeRootPrefix(path)
	if path == k8sTypes.DefaultPolicyParentPath {
		return ""
	}
	if strings.HasPrefix(path, k8sTypes.DefaultPolicyParentPath) {
		return strings.TrimPrefix(path, k8sTypes.DefaultPolicyParentPathPrefix)
	}
	return path
}

func removeRootK8sPrefixFromLabelArray(lblsIn labels.LabelArray) labels.LabelArray {
	lbl := make(labels.LabelArray, len(lblsIn))
	for i, v := range lblsIn {
		lbl[i] = labels.NewLabel(removeRootK8sPrefix(v.Key), v.Value, v.Source)
	}
	return lbl
}

// Allows returns the decision whether the node allows the From to consume the
// To in the provided search context
func (prc *RuleK8s) Allows(ctx *SearchContext) api.ConsumableDecision {
	// A decision is undecided until we encounter a DENY or ACCEPT.
	// An ACCEPT can still be overwritten by a DENY inside the same rule.
	decision := api.UNDECIDED

	fromBak := ctx.From
	ctx.From = removeRootK8sPrefixFromLabelArray(ctx.From)
	toBak := ctx.To
	ctx.To = removeRootK8sPrefixFromLabelArray(ctx.To)
	defer func() {
		ctx.From = fromBak
		ctx.To = toBak
	}()

	lbSelector, _ := metav1.LabelSelectorAsSelector(&prc.PodSelector)
	if !lbSelector.Matches(k8sLbls.Labels(ctx.To)) {
		policyTrace(ctx, "K8s rule has no coverage: [%s] for %s\n", prc.String(), ctx.To)
		return api.UNDECIDED
	}

	policyTrace(ctx, "Found coverage k8s-rule: [%s]", prc.String())

	for _, k8sAllowRule := range prc.Allow {
		switch k8sAllowRule.Allows(ctx) {
		case api.DENY:
			return api.DENY
		case api.ALWAYS_ACCEPT:
			return api.ALWAYS_ACCEPT
		case api.ACCEPT:
			decision = api.ACCEPT
		}
	}

	return decision
}

func (prc *RuleK8s) Resolve(node *Node) error {
	return nil
}

func (prc *RuleK8s) SHA256Sum() (string, error) {
	sha := sha512.New512_256()
	if err := json.NewEncoder(sha).Encode(prc); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}

func (prc *RuleK8s) CoverageSHA256Sum() (string, error) {
	lbSelector, _ := metav1.LabelSelectorAsSelector(&prc.PodSelector)
	if lbSelector.Empty() {
		return labels.LabelSliceSHA256Sum(nil)
	}
	l := labels.NewLabel("", "", "")
	l.Key = prc.PodSelector.String()
	return labels.LabelSliceSHA256Sum([]*labels.Label{l})
}
