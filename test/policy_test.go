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
				ID: "run1", Type: model.TypeContainer, State: model.StateRunning,
				CreatedAt: time.Now().Add(-48 * time.Hour), Labels: map[string]string{},
			}),
			resourceID:     "run1",
			wantAction:     model.ActionKeep,
			reasonContains: "running container",
		},
		{
			name: "running container with keep label — hardcoded protection fires before label check",
			inventory: invContainers(model.Resource{
				ID: "run-lbl", Type: model.TypeContainer, State: model.StateRunning,
				CreatedAt: time.Now().Add(-48 * time.Hour),
				Labels:    map[string]string{"dredge.keep": "true"},
			}),
			resourceID:     "run-lbl",
			wantAction:     model.ActionKeep,
			reasonContains: "running container",
		},
		{
			name: "exited container older than threshold deleted",
			inventory: invContainers(model.Resource{
				ID: "exit-old", Type: model.TypeContainer, State: model.StateExited,
				CreatedAt: time.Now().Add(-48 * time.Hour), Labels: map[string]string{},
			}),
			resourceID:     "exit-old",
			wantAction:     model.ActionDelete,
			reasonContains: "exited",
		},
		{
			name: "exited container younger than threshold kept",
			inventory: invContainers(model.Resource{
				ID: "exit-new", Type: model.TypeContainer, State: model.StateExited,
				CreatedAt: time.Now().Add(-2 * time.Hour), Labels: map[string]string{},
			}),
			resourceID:     "exit-new",
			wantAction:     model.ActionKeep,
			reasonContains: "no matching deletion rule",
		},
		{
			name: "dead container deleted immediately (OlderThan 0)",
			inventory: invContainers(model.Resource{
				ID: "dead1", Type: model.TypeContainer, State: model.StateDead,
				CreatedAt: time.Now().Add(-1 * time.Minute), Labels: map[string]string{},
			}),
			resourceID:     "dead1",
			wantAction:     model.ActionDelete,
			reasonContains: "dead",
		},
		{
			name: "label protection overrides deletion rule",
			inventory: invContainers(model.Resource{
				ID: "lbl1", Type: model.TypeContainer, State: model.StateExited,
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
				ID: "lbl2", Type: model.TypeContainer, State: model.StateExited,
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
				ID: "pg1", Name: "postgres-main", Type: model.TypeContainer, State: model.StateExited,
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
				State: model.StateDangling, Labels: map[string]string{},
			}),
			resourceID:     "img-dangle",
			wantAction:     model.ActionDelete,
			reasonContains: "dangling",
		},
		{
			name: "non-dangling image kept by dangling-only rule (recent)",
			inventory: invImages(model.Resource{
				ID: "img-used", Name: "nginx:latest", Type: model.TypeImage,
				State: model.StateUsed, CreatedAt: time.Now().Add(-2 * time.Hour), Labels: map[string]string{},
			}),
			resourceID:     "img-used",
			wantAction:     model.ActionKeep,
			reasonContains: "no matching deletion rule",
		},
		{
			name: "non-dangling image deleted when older than unused threshold",
			inventory: invImages(model.Resource{
				ID: "img-old", Name: "old-base:v1", Type: model.TypeImage,
				State: model.StateUsed, CreatedAt: time.Now().Add(-200 * time.Hour), Labels: map[string]string{},
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
				ID: "ctr-created", Type: model.TypeContainer, State: model.StateCreated,
				CreatedAt: time.Now().Add(-48 * time.Hour), Labels: map[string]string{},
			}),
			resourceID:     "ctr-created",
			wantAction:     model.ActionKeep,
			reasonContains: "no matching deletion rule",
		},
		{
			name: "image kept when its referencing container is kept (graph wiring)",
			inventory: &collector.Inventory{
				Containers: []model.Resource{
					{
						ID: "ctr-run", Type: model.TypeContainer, State: model.StateRunning,
						CreatedAt: time.Now().Add(-72 * time.Hour), Labels: map[string]string{},
					},
				},
				Images: []model.Resource{
					{
						ID: "img-ref", Name: "old-base:v2", Type: model.TypeImage,
						State: model.StateDangling,
						CreatedAt:  time.Now().Add(-200 * time.Hour),
						References: []string{"ctr-run"},
						Labels:     map[string]string{},
					},
				},
			},
			resourceID:     "img-ref",
			wantAction:     model.ActionKeep,
			reasonContains: "referenced by kept container",
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
