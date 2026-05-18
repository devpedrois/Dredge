package planner

import (
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/user/dredge/internal/model"
)

// typeOrder defines the mandatory deletion sequence.
// [SECURITY] Strict deletion order — containers before images before volumes before networks.
// Removing containers first ensures images and volumes have no live references.
var typeOrder = map[model.ResourceType]int{
	model.TypeContainer: 0,
	model.TypeImage:     1,
	model.TypeVolume:    2,
	model.TypeNetwork:   3,
}

// Planner converts a slice of Decisions into an ordered ExecutionPlan.
type Planner struct {
	logger          *slog.Logger
	protectionLabel string // "key=value" — defense-in-depth, checked after policy engine
}

// New constructs a Planner.
// protectionLabel is "key=value" from config.Protection.Label.
// Providing it enables a third independent label-protection check inside CreatePlan.
// [SECURITY] 3rd layer — label protection checked at policy engine, planner, AND sweeper.
func New(logger *slog.Logger, protectionLabel string) *Planner {
	return &Planner{logger: logger, protectionLabel: protectionLabel}
}

// CreatePlan filters Delete decisions, sorts them in the mandatory deletion order,
// and assembles an ExecutionPlan with sequential Order numbers and total size.
// [SECURITY] Plan uses identical evaluation logic as sweep — dry-run parity guaranteed.
func (p *Planner) CreatePlan(decisions []model.Decision) *model.ExecutionPlan {
	var deletions []model.Decision
	protectedCount := 0

	for _, d := range decisions {
		if d.Action == model.ActionDelete {
			// [SECURITY] 3rd-layer label check — defense-in-depth against policy engine bugs.
			if p.hasProtectionLabel(d.Resource) {
				if p.logger != nil {
					p.logger.Error("[SECURITY] protected resource reached planner — BUG in policy engine, skipping",
						"id", d.Resource.ID, "type", d.Resource.Type, "name", d.Resource.Name)
				}
				protectedCount++
				continue
			}
			deletions = append(deletions, d)
		} else {
			protectedCount++
		}
	}

	// [SECURITY] Strict deletion order — containers before images before volumes before networks.
	// Within each type, oldest resources are deleted first.
	sort.SliceStable(deletions, func(i, j int) bool {
		ti := typeOrder[deletions[i].Resource.Type]
		tj := typeOrder[deletions[j].Resource.Type]
		if ti != tj {
			return ti < tj
		}
		return deletions[i].Resource.CreatedAt.Before(deletions[j].Resource.CreatedAt)
	})

	var totalSize int64
	items := make([]model.Deletion, len(deletions))
	for idx, d := range deletions {
		totalSize += d.Resource.Size
		items[idx] = model.Deletion{
			Resource: d.Resource,
			Reason:   d.Reason,
			Order:    idx + 1,
		}
	}

	return &model.ExecutionPlan{
		Deletions:      items,
		TotalSize:      totalSize,
		ProtectedCount: protectedCount,
		Timestamp:      time.Now(),
	}
}

// hasProtectionLabel returns true when r carries the configured protection label.
// [SECURITY] 3rd-layer defense — label checked independently of policy engine and sweeper.
func (p *Planner) hasProtectionLabel(r *model.Resource) bool {
	if p.protectionLabel == "" || len(r.Labels) == 0 {
		return false
	}
	parts := strings.SplitN(p.protectionLabel, "=", 2)
	if len(parts) != 2 {
		return false
	}
	v, ok := r.Labels[parts[0]]
	return ok && v == parts[1]
}
