package policy

import (
	"fmt"
	"log/slog"
	"path/filepath"
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
		e.logger.Debug("evaluated resource",
			"id", d.Resource.ID,
			"type", d.Resource.Type,
			"action", d.Action,
			"reason", d.Reason,
		)
		decisions = append(decisions, d)
	}

	// d.Resource in each Decision points into the local all slice (heap-allocated).
	// Downstream callers must treat Resource as read-only.
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
	if r.Type == model.TypeContainer && r.State == model.StateRunning {
		return keep("running container — always protected")
	}
	// [SECURITY] Default networks (bridge, host, none) — never deleted.
	if r.Type == model.TypeNetwork && r.IsDefault {
		return keep("default Docker network — always protected")
	}

	// Step 2 — Label protection.
	// [SECURITY] Protection label is sacrosanct — checked before any deletion rule.
	if model.MatchesProtectionLabel(e.config.Protection.Label, r.Labels) {
		return keep("protected by label: " + e.config.Protection.Label)
	}

	// Step 3 — Name pattern protection.
	for _, pattern := range e.config.Protection.NamePatterns {
		matched, err := filepath.Match(pattern, r.Name)
		if err != nil {
			e.logger.Warn("invalid name pattern in protection config — pattern skipped",
				"pattern", pattern, "error", err)
			continue
		}
		if matched {
			return keep("protected by name pattern: " + pattern)
		}
	}

	// Step 4 — Policy rules.
	switch r.Type {
	case model.TypeContainer:
		for _, rule := range e.config.Policies.Containers {
			if r.State == model.ResourceState(rule.Status) && time.Since(r.CreatedAt) >= rule.OlderThan {
				return del(
					fmt.Sprintf("container status %q older than %s", rule.Status, rule.OlderThan),
					"container-rule:"+rule.Status,
				)
			}
		}
	case model.TypeImage:
		if r.State == model.StateDangling && e.config.Policies.Images.Dangling {
			return del("dangling image (<none>:<none>)", "image-rule:dangling")
		}
		threshold := e.config.Policies.Images.UnusedOlderThan
		if threshold > 0 && r.State != model.StateDangling && len(r.References) == 0 && time.Since(r.CreatedAt) >= threshold {
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

