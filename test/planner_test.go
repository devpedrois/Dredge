package test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/user/dredge/internal/model"
	"github.com/user/dredge/internal/planner"
)

func makeDecision(rtype model.ResourceType, action model.Action, createdAt time.Time, size int64) model.Decision {
	r := &model.Resource{
		ID:        "id-" + string(rtype),
		Name:      "name-" + string(rtype),
		Type:      rtype,
		CreatedAt: createdAt,
		Size:      size,
	}
	return model.Decision{Resource: r, Action: action, Reason: "test reason"}
}

func makeDecisionNamed(rtype model.ResourceType, name string, action model.Action, createdAt time.Time, size int64) model.Decision {
	r := &model.Resource{
		ID:        "id-" + name,
		Name:      name,
		Type:      rtype,
		CreatedAt: createdAt,
		Size:      size,
	}
	return model.Decision{Resource: r, Action: action, Reason: "test reason"}
}

func TestPlannerOrdersContainersBeforeImages(t *testing.T) {
	now := time.Now()
	decisions := []model.Decision{
		makeDecision(model.TypeImage, model.ActionDelete, now, 100),
		makeDecision(model.TypeContainer, model.ActionDelete, now, 50),
	}

	p := planner.New(nil)
	plan := p.CreatePlan(decisions)

	assert.Len(t, plan.Deletions, 2)
	assert.Equal(t, model.TypeContainer, plan.Deletions[0].Resource.Type)
	assert.Equal(t, model.TypeImage, plan.Deletions[1].Resource.Type)
}

func TestPlannerOrdersImagesBeforeVolumes(t *testing.T) {
	now := time.Now()
	decisions := []model.Decision{
		makeDecision(model.TypeVolume, model.ActionDelete, now, 200),
		makeDecision(model.TypeImage, model.ActionDelete, now, 100),
	}

	p := planner.New(nil)
	plan := p.CreatePlan(decisions)

	assert.Len(t, plan.Deletions, 2)
	assert.Equal(t, model.TypeImage, plan.Deletions[0].Resource.Type)
	assert.Equal(t, model.TypeVolume, plan.Deletions[1].Resource.Type)
}

func TestPlannerOrdersVolumesBeforeNetworks(t *testing.T) {
	now := time.Now()
	decisions := []model.Decision{
		makeDecision(model.TypeNetwork, model.ActionDelete, now, 0),
		makeDecision(model.TypeVolume, model.ActionDelete, now, 300),
	}

	p := planner.New(nil)
	plan := p.CreatePlan(decisions)

	assert.Len(t, plan.Deletions, 2)
	assert.Equal(t, model.TypeVolume, plan.Deletions[0].Resource.Type)
	assert.Equal(t, model.TypeNetwork, plan.Deletions[1].Resource.Type)
}

func TestPlannerCalculatesTotalSize(t *testing.T) {
	now := time.Now()
	decisions := []model.Decision{
		makeDecisionNamed(model.TypeContainer, "c1", model.ActionDelete, now, 100),
		makeDecisionNamed(model.TypeImage, "i1", model.ActionDelete, now, 200),
		makeDecisionNamed(model.TypeVolume, "v1", model.ActionDelete, now, 300),
	}

	p := planner.New(nil)
	plan := p.CreatePlan(decisions)

	assert.Equal(t, int64(600), plan.TotalSize)
}

func TestPlannerCountsProtectedResources(t *testing.T) {
	now := time.Now()
	decisions := []model.Decision{
		makeDecisionNamed(model.TypeContainer, "c1", model.ActionDelete, now, 50),
		makeDecisionNamed(model.TypeContainer, "c2", model.ActionKeep, now, 50),
		makeDecisionNamed(model.TypeImage, "i1", model.ActionKeep, now, 100),
		makeDecisionNamed(model.TypeVolume, "v1", model.ActionDelete, now, 200),
		makeDecisionNamed(model.TypeVolume, "v2", model.ActionKeep, now, 0),
	}

	p := planner.New(nil)
	plan := p.CreatePlan(decisions)

	assert.Equal(t, 3, plan.ProtectedCount)
	assert.Len(t, plan.Deletions, 2)
}

func TestPlannerEmptyDecisionsProduceEmptyPlan(t *testing.T) {
	p := planner.New(nil)
	plan := p.CreatePlan([]model.Decision{})

	assert.Empty(t, plan.Deletions)
	assert.Equal(t, int64(0), plan.TotalSize)
	assert.Equal(t, 0, plan.ProtectedCount)
}

func TestPlannerNumbersDeletionsSequentially(t *testing.T) {
	now := time.Now()
	decisions := []model.Decision{
		makeDecisionNamed(model.TypeContainer, "c1", model.ActionDelete, now, 10),
		makeDecisionNamed(model.TypeContainer, "c2", model.ActionDelete, now, 10),
		makeDecisionNamed(model.TypeImage, "i1", model.ActionDelete, now, 10),
		makeDecisionNamed(model.TypeVolume, "v1", model.ActionDelete, now, 10),
	}

	p := planner.New(nil)
	plan := p.CreatePlan(decisions)

	assert.Len(t, plan.Deletions, 4)
	for i, d := range plan.Deletions {
		assert.Equal(t, i+1, d.Order)
	}
}

func TestPlannerWithinTypeSortsByCreatedAt(t *testing.T) {
	oldest := time.Now().Add(-72 * time.Hour)
	middle := time.Now().Add(-48 * time.Hour)
	newest := time.Now().Add(-24 * time.Hour)

	decisions := []model.Decision{
		makeDecisionNamed(model.TypeContainer, "newest", model.ActionDelete, newest, 10),
		makeDecisionNamed(model.TypeContainer, "oldest", model.ActionDelete, oldest, 10),
		makeDecisionNamed(model.TypeContainer, "middle", model.ActionDelete, middle, 10),
	}

	p := planner.New(nil)
	plan := p.CreatePlan(decisions)

	assert.Len(t, plan.Deletions, 3)
	assert.Equal(t, "oldest", plan.Deletions[0].Resource.Name)
	assert.Equal(t, "middle", plan.Deletions[1].Resource.Name)
	assert.Equal(t, "newest", plan.Deletions[2].Resource.Name)
}

func TestPlannerFullOrderContainersImagesVolumesNetworks(t *testing.T) {
	now := time.Now()
	decisions := []model.Decision{
		makeDecision(model.TypeNetwork, model.ActionDelete, now, 0),
		makeDecision(model.TypeVolume, model.ActionDelete, now, 100),
		makeDecision(model.TypeImage, model.ActionDelete, now, 200),
		makeDecision(model.TypeContainer, model.ActionDelete, now, 50),
	}

	p := planner.New(nil)
	plan := p.CreatePlan(decisions)

	expectedOrder := []model.ResourceType{
		model.TypeContainer,
		model.TypeImage,
		model.TypeVolume,
		model.TypeNetwork,
	}
	for i, d := range plan.Deletions {
		assert.Equal(t, expectedOrder[i], d.Resource.Type)
	}
}

func TestPlannerOnlyDeleteDecisionsIncluded(t *testing.T) {
	now := time.Now()
	decisions := []model.Decision{
		makeDecisionNamed(model.TypeContainer, "keep-me", model.ActionKeep, now, 100),
		makeDecisionNamed(model.TypeImage, "delete-me", model.ActionDelete, now, 200),
	}

	p := planner.New(nil)
	plan := p.CreatePlan(decisions)

	assert.Len(t, plan.Deletions, 1)
	assert.Equal(t, "delete-me", plan.Deletions[0].Resource.Name)
}
