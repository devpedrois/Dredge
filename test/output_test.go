package test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/user/dredge/internal/model"
	"github.com/user/dredge/internal/output"
)

func makePlan(deletions []model.Deletion, protected int) *model.ExecutionPlan {
	var total int64
	for _, d := range deletions {
		total += d.Resource.Size
	}
	return &model.ExecutionPlan{
		Deletions:      deletions,
		TotalSize:      total,
		ProtectedCount: protected,
		Timestamp:      time.Now(),
	}
}

func makeDeletion(rtype model.ResourceType, name string, size int64, reason string, order int) model.Deletion {
	return model.Deletion{
		Resource: &model.Resource{
			ID:        "id-" + name,
			Name:      name,
			Type:      rtype,
			Size:      size,
			CreatedAt: time.Now().Add(-48 * time.Hour),
		},
		Reason: reason,
		Order:  order,
	}
}

func TestTableOutputContainsAllEntries(t *testing.T) {
	deletions := []model.Deletion{
		makeDeletion(model.TypeContainer, "my-old-app", 150*1024*1024, "exited > 24h", 1),
		makeDeletion(model.TypeImage, "stale-image", 1200*1024*1024, "dangling image", 2),
		makeDeletion(model.TypeVolume, "old-data", 500*1024*1024, "orphaned volume", 3),
	}
	plan := makePlan(deletions, 2)

	var buf bytes.Buffer
	output.FormatPlanTable(plan, &buf)
	out := buf.String()

	assert.Contains(t, out, "my-old-app")
	assert.Contains(t, out, "stale-image")
	assert.Contains(t, out, "old-data")
}

func TestTableOutputShowsSummary(t *testing.T) {
	deletions := []model.Deletion{
		makeDeletion(model.TypeContainer, "c1", 100*1024*1024, "exited > 24h", 1),
	}
	plan := makePlan(deletions, 1)

	var buf bytes.Buffer
	output.FormatPlanTable(plan, &buf)
	out := buf.String()

	assert.Contains(t, out, "Will delete")
	assert.Contains(t, out, "Space recoverable")
}

func TestTableOutputShowsReasonColumn(t *testing.T) {
	deletions := []model.Deletion{
		makeDeletion(model.TypeContainer, "c1", 50*1024*1024, "exited > 24h", 1),
	}
	plan := makePlan(deletions, 0)

	var buf bytes.Buffer
	output.FormatPlanTable(plan, &buf)
	out := buf.String()

	assert.Contains(t, out, "exited > 24h")
}

func TestEmptyPlanShowsTidyMessage(t *testing.T) {
	plan := makePlan([]model.Deletion{}, 0)

	var buf bytes.Buffer
	output.FormatPlanTable(plan, &buf)
	out := buf.String()

	assert.Contains(t, out, "Nothing to clean")
}

func TestJSONOutputProducesValidJSON(t *testing.T) {
	deletions := []model.Deletion{
		makeDeletion(model.TypeContainer, "c1", 100*1024*1024, "exited > 24h", 1),
		makeDeletion(model.TypeImage, "i1", 200*1024*1024, "dangling image", 2),
	}
	plan := makePlan(deletions, 3)

	var buf bytes.Buffer
	err := output.FormatPlanJSON(plan, &buf)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &parsed)
	require.NoError(t, err)

	assert.Contains(t, parsed, "deletions")
	assert.Contains(t, parsed, "total_size")
	assert.Contains(t, parsed, "protected_count")
}

func TestJSONOutputContainsResourceNames(t *testing.T) {
	deletions := []model.Deletion{
		makeDeletion(model.TypeContainer, "my-container", 50*1024*1024, "exited > 24h", 1),
	}
	plan := makePlan(deletions, 0)

	var buf bytes.Buffer
	err := output.FormatPlanJSON(plan, &buf)
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "my-container")
}

func TestTableOutputShowsFooterWithSweepHint(t *testing.T) {
	deletions := []model.Deletion{
		makeDeletion(model.TypeContainer, "c1", 100*1024*1024, "exited > 24h", 1),
	}
	plan := makePlan(deletions, 0)

	var buf bytes.Buffer
	output.FormatPlanTable(plan, &buf)
	out := buf.String()

	assert.True(t,
		strings.Contains(out, "dredge sweep") || strings.Contains(out, "sweep"),
		"footer should hint at sweep command",
	)
}

func TestTableOutputShowsResourceTypes(t *testing.T) {
	deletions := []model.Deletion{
		makeDeletion(model.TypeContainer, "c1", 10*1024*1024, "exited > 24h", 1),
		makeDeletion(model.TypeImage, "i1", 20*1024*1024, "dangling", 2),
		makeDeletion(model.TypeVolume, "v1", 30*1024*1024, "orphaned", 3),
		makeDeletion(model.TypeNetwork, "n1", 0, "unused", 4),
	}
	plan := makePlan(deletions, 0)

	var buf bytes.Buffer
	output.FormatPlanTable(plan, &buf)
	out := buf.String()

	assert.Contains(t, out, "container")
	assert.Contains(t, out, "image")
	assert.Contains(t, out, "volume")
	assert.Contains(t, out, "network")
}
