package planner

import (
	"log/slog"
	"sort"
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
	logger *slog.Logger
}

// New constructs a Planner. logger may be nil (no-op).
func New(logger *slog.Logger) *Planner {
	return &Planner{logger: logger}
}

// CreatePlan filters Delete decisions, sorts them in the mandatory deletion order,
// and assembles an ExecutionPlan with sequential Order numbers and total size.
// [SECURITY] Plan uses identical evaluation logic as sweep — dry-run parity guaranteed.
func (p *Planner) CreatePlan(decisions []model.Decision) *model.ExecutionPlan {
	var deletions []model.Decision
	protectedCount := 0

	for _, d := range decisions {
		if d.Action == model.ActionDelete {
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
