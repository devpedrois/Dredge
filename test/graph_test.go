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
		name       string
		input      []model.Decision
		imageID    string
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
