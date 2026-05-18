# Policy Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the policy engine (evaluate each Docker resource against config rules, deny-by-default) and the dependency graph resolver (protect images referenced by kept containers).

**Architecture:** Two files in `internal/policy/`: `engine.go` holds `Engine.Evaluate(inventory)` which runs a 5-step evaluation per resource (hardcoded protections → label → name pattern → policy rules → keep), then delegates to `graph.go`'s `ResolveGraph()` for a second pass that protects images whose containers are kept. Both are tested via table-driven unit tests in `test/` with no real Docker required.

**Tech Stack:** Go 1.22, stdlib only (`path/filepath` for glob, `strings`, `time`, `fmt`), `github.com/stretchr/testify` for assertions.

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `internal/policy/graph.go` | Create | `ResolveGraph()` — second-pass dependency check |
| `internal/policy/engine.go` | Create | `Engine`, `New()`, `Evaluate()` — 5-step per-resource eval |
| `test/graph_test.go` | Create | 4 table-driven graph tests |
| `test/policy_test.go` | Create | 15 table-driven engine tests |

---

## Task 1: Write failing graph tests

**Files:**
- Create: `test/graph_test.go`

- [ ] **Step 1: Create test file**

```go
package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/user/dredge/internal/model"
	"github.com/user/dredge/internal/policy"
)

func mkDecision(id string, typ model.ResourceType, name string, refs []string, action model.Action) model.Decision {
	return model.Decision{
		Resource: &model.Resource{ID: id, Type: typ, Name: name, References: refs},
		Action:   action,
		Reason:   "test",
	}
}

func findDecision(decisions []model.Decision, id string) *model.Decision {
	for i := range decisions {
		if decisions[i].Resource.ID == id {
			return &decisions[i]
		}
	}
	return nil
}

func TestResolveGraph(t *testing.T) {
	tests := []struct {
		name      string
		input     []model.Decision
		imageID   string
		wantAction model.Action
	}{
		{
			name: "image kept when referenced by kept container",
			input: []model.Decision{
				mkDecision("ctr1", model.TypeContainer, "web", nil, model.ActionKeep),
				mkDecision("img1", model.TypeImage, "nginx:latest", []string{"ctr1"}, model.ActionDelete),
			},
			imageID:    "img1",
			wantAction: model.ActionKeep,
		},
		{
			name: "image deleted when all referencing containers also deleted",
			input: []model.Decision{
				mkDecision("ctr2", model.TypeContainer, "app", nil, model.ActionDelete),
				mkDecision("ctr3", model.TypeContainer, "worker", nil, model.ActionDelete),
				mkDecision("img2", model.TypeImage, "alpine:3", []string{"ctr2", "ctr3"}, model.ActionDelete),
			},
			imageID:    "img2",
			wantAction: model.ActionDelete,
		},
		{
			name: "image with no references can be deleted",
			input: []model.Decision{
				mkDecision("img3", model.TypeImage, "<none>:<none>", nil, model.ActionDelete),
			},
			imageID:    "img3",
			wantAction: model.ActionDelete,
		},
		{
			name: "mixed references: one kept container protects image",
			input: []model.Decision{
				mkDecision("ctr4", model.TypeContainer, "app1", nil, model.ActionDelete),
				mkDecision("ctr5", model.TypeContainer, "app2", nil, model.ActionDelete),
				mkDecision("ctr6", model.TypeContainer, "alive", nil, model.ActionKeep),
				mkDecision("img4", model.TypeImage, "ubuntu:22", []string{"ctr4", "ctr5", "ctr6"}, model.ActionDelete),
			},
			imageID:    "img4",
			wantAction: model.ActionKeep,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := policy.ResolveGraph(tc.input)
			d := findDecision(result, tc.imageID)
			require.NotNil(t, d, "image %s not found in result", tc.imageID)
			assert.Equal(t, tc.wantAction, d.Action)
		})
	}
}
```

- [ ] **Step 2: Run — expect compile error (policy package missing)**

```bash
cd /home/devpedrois/projetos/go/Dredge && go test ./test/ 2>&1 | head -20
```

Expected: `cannot find package "github.com/user/dredge/internal/policy"`

---

## Task 2: Implement graph.go

**Files:**
- Create: `internal/policy/graph.go`

- [ ] **Step 1: Create stub so tests compile**

```go
package policy

import "github.com/user/dredge/internal/model"

// ResolveGraph performs a second-pass over decisions to enforce the dependency
// graph rule: an image cannot be deleted if any of its referencing containers
// will be kept.
// [SECURITY] Dependency graph — image protected because a kept container needs it.
func ResolveGraph(decisions []model.Decision) []model.Decision {
	return decisions
}
```

- [ ] **Step 2: Run tests — expect 2 failures (stub returns input unchanged)**

```bash
cd /home/devpedrois/projetos/go/Dredge && go test ./test/ -run TestResolveGraph -v 2>&1
```

Expected: FAIL for "image kept when referenced by kept container" and "mixed references".

- [ ] **Step 3: Implement ResolveGraph**

```go
package policy

import "github.com/user/dredge/internal/model"

// ResolveGraph performs a second-pass over decisions to enforce the dependency
// graph rule: an image cannot be deleted if any of its referencing containers
// will be kept.
// [SECURITY] Dependency graph — image protected because a kept container needs it.
func ResolveGraph(decisions []model.Decision) []model.Decision {
	// Build the set of containers marked for deletion and a name lookup map.
	deletedContainers := make(map[string]bool, len(decisions))
	containerNames := make(map[string]string, len(decisions))

	for _, d := range decisions {
		if d.Resource.Type != model.TypeContainer {
			continue
		}
		containerNames[d.Resource.ID] = d.Resource.Name
		if d.Action == model.ActionDelete {
			deletedContainers[d.Resource.ID] = true
		}
	}

	result := make([]model.Decision, len(decisions))
	copy(result, decisions)

	for i, d := range result {
		if d.Resource.Type != model.TypeImage || d.Action != model.ActionDelete {
			continue
		}
		// If any referencing container is NOT being deleted, protect the image.
		for _, cID := range d.Resource.References {
			if !deletedContainers[cID] {
				result[i].Action = model.ActionKeep
				result[i].Reason = "referenced by kept container: " + containerNames[cID]
				result[i].RuleMatch = ""
				break
			}
		}
	}

	return result
}
```

- [ ] **Step 4: Run graph tests — expect all PASS**

```bash
cd /home/devpedrois/projetos/go/Dredge && go test ./test/ -run TestResolveGraph -v 2>&1
```

Expected: 4 subtests PASS.

---

## Task 3: Write failing engine tests

**Files:**
- Create: `test/policy_test.go`

- [ ] **Step 1: Create test file**

```go
package test

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/user/dredge/internal/collector"
	"github.com/user/dredge/internal/config"
	"github.com/user/dredge/internal/model"
	"github.com/user/dredge/internal/policy"
)

func newTestEngine(cfg *config.Config) *policy.Engine {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return policy.New(cfg, logger)
}

func fullPolicyConfig() *config.Config {
	return &config.Config{
		Docker: config.DockerConfig{Timeout: 30 * time.Second},
		Policies: config.PoliciesConfig{
			Containers: []config.ContainerRule{
				{Status: "exited", OlderThan: 24 * time.Hour},
				{Status: "dead", OlderThan: 0},
			},
			Images:   config.ImagePolicy{Dangling: true, UnusedOlderThan: 168 * time.Hour},
			Volumes:  config.VolumePolicy{Orphaned: true},
			Networks: config.NetworkPolicy{Unused: true},
		},
		Protection: config.ProtectionConfig{
			Label:        "dredge.keep=true",
			NamePatterns: []string{"postgres*", "redis*", "production-*"},
		},
	}
}

func invContainers(rs ...model.Resource) *collector.Inventory {
	return &collector.Inventory{Containers: rs}
}
func invImages(rs ...model.Resource) *collector.Inventory {
	return &collector.Inventory{Images: rs}
}
func invVolumes(rs ...model.Resource) *collector.Inventory {
	return &collector.Inventory{Volumes: rs}
}
func invNetworks(rs ...model.Resource) *collector.Inventory {
	return &collector.Inventory{Networks: rs}
}

// findDecision is defined in graph_test.go (same package). No redeclaration needed.

func TestEngine_Evaluate(t *testing.T) {
	cfg := fullPolicyConfig()
	engine := newTestEngine(cfg)

	tests := []struct {
		name           string
		inventory      *collector.Inventory
		resourceID     string
		wantAction     model.Action
		reasonContains string
	}{
		{
			name: "running container always protected",
			inventory: invContainers(model.Resource{
				ID: "run1", Type: model.TypeContainer, State: "running",
				CreatedAt: time.Now().Add(-48 * time.Hour), Labels: map[string]string{},
			}),
			resourceID:     "run1",
			wantAction:     model.ActionKeep,
			reasonContains: "running container",
		},
		{
			name: "exited container older than threshold deleted",
			inventory: invContainers(model.Resource{
				ID: "exit-old", Type: model.TypeContainer, State: "exited",
				CreatedAt: time.Now().Add(-48 * time.Hour), Labels: map[string]string{},
			}),
			resourceID:     "exit-old",
			wantAction:     model.ActionDelete,
			reasonContains: "exited",
		},
		{
			name: "exited container younger than threshold kept",
			inventory: invContainers(model.Resource{
				ID: "exit-new", Type: model.TypeContainer, State: "exited",
				CreatedAt: time.Now().Add(-2 * time.Hour), Labels: map[string]string{},
			}),
			resourceID:     "exit-new",
			wantAction:     model.ActionKeep,
			reasonContains: "no matching deletion rule",
		},
		{
			name: "dead container deleted immediately (OlderThan 0)",
			inventory: invContainers(model.Resource{
				ID: "dead1", Type: model.TypeContainer, State: "dead",
				CreatedAt: time.Now().Add(-1 * time.Minute), Labels: map[string]string{},
			}),
			resourceID:     "dead1",
			wantAction:     model.ActionDelete,
			reasonContains: "dead",
		},
		{
			name: "label protection overrides deletion rule",
			inventory: invContainers(model.Resource{
				ID: "lbl1", Type: model.TypeContainer, State: "exited",
				CreatedAt: time.Now().Add(-48 * time.Hour),
				Labels:    map[string]string{"dredge.keep": "true"},
			}),
			resourceID:     "lbl1",
			wantAction:     model.ActionKeep,
			reasonContains: "protected by label",
		},
		{
			name: "label with wrong value does not protect",
			inventory: invContainers(model.Resource{
				ID: "lbl2", Type: model.TypeContainer, State: "exited",
				CreatedAt: time.Now().Add(-48 * time.Hour),
				Labels:    map[string]string{"dredge.keep": "false"},
			}),
			resourceID:     "lbl2",
			wantAction:     model.ActionDelete,
			reasonContains: "exited",
		},
		{
			name: "name pattern protection overrides deletion rule",
			inventory: invContainers(model.Resource{
				ID: "pg1", Name: "postgres-main", Type: model.TypeContainer, State: "exited",
				CreatedAt: time.Now().Add(-48 * time.Hour), Labels: map[string]string{},
			}),
			resourceID:     "pg1",
			wantAction:     model.ActionKeep,
			reasonContains: "protected by name pattern",
		},
		{
			name: "dangling image deleted",
			inventory: invImages(model.Resource{
				ID: "img-dangle", Name: "<none>:<none>", Type: model.TypeImage,
				State: "dangling", Labels: map[string]string{},
			}),
			resourceID:     "img-dangle",
			wantAction:     model.ActionDelete,
			reasonContains: "dangling",
		},
		{
			name: "non-dangling image kept by dangling-only rule (recent)",
			inventory: invImages(model.Resource{
				ID: "img-used", Name: "nginx:latest", Type: model.TypeImage,
				State: "used", CreatedAt: time.Now().Add(-2 * time.Hour), Labels: map[string]string{},
			}),
			resourceID:     "img-used",
			wantAction:     model.ActionKeep,
			reasonContains: "no matching deletion rule",
		},
		{
			name: "non-dangling image deleted when older than unused threshold",
			inventory: invImages(model.Resource{
				ID: "img-old", Name: "old-base:v1", Type: model.TypeImage,
				State: "used", CreatedAt: time.Now().Add(-200 * time.Hour), Labels: map[string]string{},
			}),
			resourceID:     "img-old",
			wantAction:     model.ActionDelete,
			reasonContains: "unused image older than",
		},
		{
			name: "default network always protected",
			inventory: invNetworks(model.Resource{
				ID: "net-bridge", Name: "bridge", Type: model.TypeNetwork,
				IsDefault: true, Labels: map[string]string{},
			}),
			resourceID:     "net-bridge",
			wantAction:     model.ActionKeep,
			reasonContains: "default Docker network",
		},
		{
			name: "unused custom network deleted",
			inventory: invNetworks(model.Resource{
				ID: "net-custom", Name: "my-net", Type: model.TypeNetwork,
				IsDefault: false, References: nil, Labels: map[string]string{},
			}),
			resourceID:     "net-custom",
			wantAction:     model.ActionDelete,
			reasonContains: "unused custom network",
		},
		{
			name: "custom network with connected containers kept",
			inventory: invNetworks(model.Resource{
				ID: "net-busy", Name: "busy-net", Type: model.TypeNetwork,
				IsDefault: false, References: []string{"ctr123"}, Labels: map[string]string{},
			}),
			resourceID:     "net-busy",
			wantAction:     model.ActionKeep,
			reasonContains: "no matching deletion rule",
		},
		{
			name: "orphaned volume deleted",
			inventory: invVolumes(model.Resource{
				ID: "vol-orphan", Name: "orphan-vol", Type: model.TypeVolume,
				References: nil, Labels: map[string]string{},
			}),
			resourceID:     "vol-orphan",
			wantAction:     model.ActionDelete,
			reasonContains: "orphaned volume",
		},
		{
			name: "non-orphaned volume kept",
			inventory: invVolumes(model.Resource{
				ID: "vol-used", Name: "used-vol", Type: model.TypeVolume,
				References: []string{"ctr123"}, Labels: map[string]string{},
			}),
			resourceID:     "vol-used",
			wantAction:     model.ActionKeep,
			reasonContains: "no matching deletion rule",
		},
		{
			name: "no matching rule means keep (created container, no created rule)",
			inventory: invContainers(model.Resource{
				ID: "ctr-created", Type: model.TypeContainer, State: "created",
				CreatedAt: time.Now().Add(-48 * time.Hour), Labels: map[string]string{},
			}),
			resourceID:     "ctr-created",
			wantAction:     model.ActionKeep,
			reasonContains: "no matching deletion rule",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decisions := engine.Evaluate(tc.inventory)
			d := findDecision(decisions, tc.resourceID)
			require.NotNil(t, d, "resource %s not found in decisions", tc.resourceID)
			assert.Equal(t, tc.wantAction, d.Action, "action mismatch: reason=%q", d.Reason)
			assert.Contains(t, d.Reason, tc.reasonContains)
		})
	}
}
```

- [ ] **Step 2: Run — expect compile error (Engine type missing)**

```bash
cd /home/devpedrois/projetos/go/Dredge && go test ./test/ -run TestEngine 2>&1 | head -20
```

Expected: `undefined: policy.New` or `undefined: policy.Engine`

---

## Task 4: Implement engine.go

**Files:**
- Create: `internal/policy/engine.go`

- [ ] **Step 1: Create engine.go stub to make tests compile**

```go
package policy

import (
	"log/slog"

	"github.com/user/dredge/internal/collector"
	"github.com/user/dredge/internal/config"
	"github.com/user/dredge/internal/model"
)

type Engine struct {
	config *config.Config
	logger *slog.Logger
}

func New(cfg *config.Config, logger *slog.Logger) *Engine {
	return &Engine{config: cfg, logger: logger}
}

func (e *Engine) Evaluate(inventory *collector.Inventory) []model.Decision {
	return nil
}
```

- [ ] **Step 2: Run — expect compile success, all tests FAIL**

```bash
cd /home/devpedrois/projetos/go/Dredge && go test ./test/ -run TestEngine -v 2>&1 | tail -20
```

Expected: all 16 subtests FAIL with "resource X not found in decisions".

- [ ] **Step 3: Implement Evaluate and evaluate helpers**

```go
package policy

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/user/dredge/internal/collector"
	"github.com/user/dredge/internal/config"
	"github.com/user/dredge/internal/model"
)

// Engine evaluates each Docker resource against the configured policies.
type Engine struct {
	config *config.Config
	logger *slog.Logger
}

// New constructs an Engine with the given config and logger.
func New(cfg *config.Config, logger *slog.Logger) *Engine {
	return &Engine{config: cfg, logger: logger}
}

// Evaluate runs the full evaluation pipeline over all resources in the inventory.
// Each resource is evaluated individually, then ResolveGraph runs a second pass
// to protect images whose referencing containers are kept.
func (e *Engine) Evaluate(inventory *collector.Inventory) []model.Decision {
	all := make([]model.Resource, 0,
		len(inventory.Containers)+len(inventory.Images)+len(inventory.Volumes)+len(inventory.Networks))
	all = append(all, inventory.Containers...)
	all = append(all, inventory.Images...)
	all = append(all, inventory.Volumes...)
	all = append(all, inventory.Networks...)

	decisions := make([]model.Decision, 0, len(all))
	for i := range all {
		d := e.evaluate(&all[i])
		e.logger.Debug("evaluated resource", "id", d.Resource.ID, "type", d.Resource.Type, "action", d.Action, "reason", d.Reason)
		decisions = append(decisions, d)
	}

	return ResolveGraph(decisions)
}

func (e *Engine) evaluate(r *model.Resource) model.Decision {
	keep := func(reason string) model.Decision {
		return model.Decision{Resource: r, Action: model.ActionKeep, Reason: reason}
	}
	del := func(reason, rule string) model.Decision {
		return model.Decision{Resource: r, Action: model.ActionDelete, Reason: reason, RuleMatch: rule}
	}

	// Step 1 — Hardcoded protections checked before any config-driven rule.
	// [SECURITY] Running container protection — hardcoded, never configurable.
	if r.Type == model.TypeContainer && r.State == "running" {
		return keep("running container — always protected")
	}
	// [SECURITY] Default networks (bridge, host, none) — never deleted.
	if r.Type == model.TypeNetwork && r.IsDefault {
		return keep("default Docker network — always protected")
	}

	// Step 2 — Label protection.
	// [SECURITY] Protection label is sacrosanct — checked before any deletion rule.
	if e.matchesProtectionLabel(r) {
		return keep("protected by label: " + e.config.Protection.Label)
	}

	// Step 3 — Name pattern protection.
	for _, pattern := range e.config.Protection.NamePatterns {
		if matched, _ := filepath.Match(pattern, r.Name); matched {
			return keep("protected by name pattern: " + pattern)
		}
	}

	// Step 4 — Policy rules.
	switch r.Type {
	case model.TypeContainer:
		for _, rule := range e.config.Policies.Containers {
			if r.State == rule.Status && time.Since(r.CreatedAt) > rule.OlderThan {
				return del(
					fmt.Sprintf("container status %q older than %s", rule.Status, rule.OlderThan),
					"container-rule:"+rule.Status,
				)
			}
		}
	case model.TypeImage:
		if r.State == "dangling" && e.config.Policies.Images.Dangling {
			return del("dangling image (<none>:<none>)", "image-rule:dangling")
		}
		threshold := e.config.Policies.Images.UnusedOlderThan
		if threshold > 0 && r.State != "dangling" && time.Since(r.CreatedAt) > threshold {
			return del(fmt.Sprintf("unused image older than %s", threshold), "image-rule:unused")
		}
	case model.TypeVolume:
		// [SECURITY] Orphan check uses References populated by collector.ResolveReferences.
		if e.config.Policies.Volumes.Orphaned && len(r.References) == 0 {
			return del("orphaned volume", "volume-rule:orphaned")
		}
	case model.TypeNetwork:
		// [SECURITY] Default networks are protected in step 1; only custom networks reach here.
		if e.config.Policies.Networks.Unused && !r.IsDefault && len(r.References) == 0 {
			return del("unused custom network", "network-rule:unused")
		}
	}

	// Step 5 — Default: keep.
	// [SECURITY] Deny-by-default — resources without matching rules are always kept.
	return keep("no matching deletion rule")
}

// matchesProtectionLabel returns true when the resource carries the configured protection label.
// [SECURITY] Label format "key=value" is validated at config load time; SplitN is safe here.
func (e *Engine) matchesProtectionLabel(r *model.Resource) bool {
	if e.config.Protection.Label == "" {
		return false
	}
	parts := strings.SplitN(e.config.Protection.Label, "=", 2)
	if len(parts) != 2 {
		return false
	}
	key, val := parts[0], parts[1]
	v, ok := r.Labels[key]
	return ok && v == val
}
```

- [ ] **Step 4: Run engine tests — expect all PASS**

```bash
cd /home/devpedrois/projetos/go/Dredge && go test ./test/ -run TestEngine -v 2>&1
```

Expected: 16 subtests PASS.

---

## Task 5: Run full test suite and commit

- [ ] **Step 1: Run all tests**

```bash
cd /home/devpedrois/projetos/go/Dredge && go test ./... 2>&1
```

Expected: `ok` for all packages. Zero failures.

- [ ] **Step 2: Run vet**

```bash
cd /home/devpedrois/projetos/go/Dredge && go vet ./... 2>&1
```

Expected: no output (zero warnings).

- [ ] **Step 3: Verify security invariants**

```bash
cd /home/devpedrois/projetos/go/Dredge && go test ./test/ -run "TestEngine_Evaluate/running_container_always_protected" -v 2>&1
cd /home/devpedrois/projetos/go/Dredge && go test ./test/ -run "TestEngine_Evaluate/label_protection_overrides_deletion_rule" -v 2>&1
cd /home/devpedrois/projetos/go/Dredge && go test ./test/ -run "TestResolveGraph/image_kept_when_referenced_by_kept_container" -v 2>&1
```

Expected: all 3 PASS.

- [ ] **Step 4: Commit**

```bash
cd /home/devpedrois/projetos/go/Dredge && git add internal/policy/engine.go internal/policy/graph.go test/policy_test.go test/graph_test.go
git commit -m "feat(policy): policy engine, label protection and dependency graph"
```
