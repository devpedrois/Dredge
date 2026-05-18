package output

import (
	"encoding/json"
	"io"
	"time"

	"github.com/user/dredge/internal/model"
)

// planJSON is the serializable representation of an ExecutionPlan.
// Uses snake_case keys for pipeline-friendly output.
type planJSON struct {
	Timestamp      time.Time     `json:"timestamp"`
	TotalSize      int64         `json:"total_size"`
	ProtectedCount int           `json:"protected_count"`
	Deletions      []deletionJSON `json:"deletions"`
}

type deletionJSON struct {
	Order  int          `json:"order"`
	Type   string       `json:"type"`
	ID     string       `json:"id"`
	Name   string       `json:"name"`
	Size   int64        `json:"size"`
	Reason string       `json:"reason"`
}

// FormatPlanJSON encodes the execution plan as pretty-printed JSON to w.
func FormatPlanJSON(plan *model.ExecutionPlan, w io.Writer) error {
	deletions := make([]deletionJSON, len(plan.Deletions))
	for i, d := range plan.Deletions {
		deletions[i] = deletionJSON{
			Order:  d.Order,
			Type:   string(d.Resource.Type),
			ID:     d.Resource.ID,
			Name:   d.Resource.Name,
			Size:   d.Resource.Size,
			Reason: d.Reason,
		}
	}

	out := planJSON{
		Timestamp:      plan.Timestamp,
		TotalSize:      plan.TotalSize,
		ProtectedCount: plan.ProtectedCount,
		Deletions:      deletions,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
