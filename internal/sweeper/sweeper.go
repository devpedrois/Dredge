package sweeper

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/user/dredge/internal/model"
)

// DockerClient is the interface the Sweeper needs to verify and delete resources.
// Defined here so unit tests can mock it without a live Docker daemon.
type DockerClient interface {
	RemoveContainer(ctx context.Context, id string) error
	RemoveImage(ctx context.Context, id string) error
	RemoveVolume(ctx context.Context, name string) error
	RemoveNetwork(ctx context.Context, id string) error
	// Inspect methods for TOCTOU re-check.
	// [SECURITY] Re-verify before each deletion — Docker state can change between plan and sweep.
	InspectContainer(ctx context.Context, id string) (exists bool, state string, err error)
	InspectImage(ctx context.Context, id string) (exists bool, err error)
	InspectVolume(ctx context.Context, name string) (exists bool, err error)
	InspectNetwork(ctx context.Context, id string) (exists bool, err error)
}

// Sweeper executes an ExecutionPlan by deleting resources one by one.
type Sweeper struct {
	client          DockerClient
	logger          *slog.Logger
	protectionLabel string // "key=value" from config.Protection.Label
}

// New constructs a Sweeper.
func New(client DockerClient, logger *slog.Logger, protectionLabel string) *Sweeper {
	return &Sweeper{
		client:          client,
		logger:          logger,
		protectionLabel: protectionLabel,
	}
}

// Execute runs all deletions in the plan.
// Fail-forward: a single deletion error does not abort the sweep.
// [SECURITY] Fail-forward — one failure does not abort the entire sweep.
func (s *Sweeper) Execute(ctx context.Context, plan *model.ExecutionPlan) *model.SweepResult {
	start := time.Now()
	result := &model.SweepResult{Plan: plan}

	for _, deletion := range plan.Deletions {
		r := deletion.Resource

		// [SECURITY] Empty ID/name is a Docker API anomaly — skip rather than risk a wrong deletion.
		switch r.Type {
		case model.TypeVolume:
			if r.Name == "" {
				s.logger.Warn("[SECURITY] volume resource has empty name — skipping", "type", r.Type)
				continue
			}
		default:
			if r.ID == "" {
				s.logger.Warn("[SECURITY] resource has empty ID — skipping", "type", r.Type, "name", r.Name)
				continue
			}
		}

		// [SECURITY] Re-verify resource state before each deletion — TOCTOU defense.
		// Docker state can change between when the plan was built and now.
		exists, currentState := s.verifyResource(ctx, r)
		if !exists {
			s.logger.Warn("resource vanished before deletion — skipping",
				"id", r.ID, "type", r.Type, "name", r.Name)
			continue
		}
		// [SECURITY] TOCTOU: container may have started between plan and sweep.
		if r.Type == model.TypeContainer && currentState == "running" {
			s.logger.Warn("[SECURITY] container changed to running — skipping",
				"id", r.ID, "name", r.Name)
			continue
		}

		// [SECURITY] Triple-check protection label at sweeper level — safety net for policy engine bugs.
		// Label is also checked in the policy engine and planner (three independent layers).
		if s.hasProtectionLabel(r) {
			s.logger.Error("[SECURITY] protected resource reached sweeper — BUG in policy engine, skipping",
				"id", r.ID, "type", r.Type, "name", r.Name, "label", s.protectionLabel)
			continue
		}

		if err := s.deleteResource(ctx, r); err != nil {
			s.logger.Error("failed to delete resource",
				"id", r.ID, "type", r.Type, "name", r.Name, "error", err)
			// [SECURITY] Fail-forward — continue with next resource after failure.
			result.Failed = append(result.Failed, model.DeletionError{
				Deletion: deletion,
				Error:    err.Error(),
			})
			continue
		}

		// [SECURITY] Audit log — every deletion recorded with full context. No secrets logged.
		s.logger.Info("resource deleted",
			"action", "delete",
			"type", string(r.Type),
			"id", r.ID,
			"name", r.Name,
			"size", r.Size,
			"reason", deletion.Reason,
		)
		result.Succeeded = append(result.Succeeded, deletion)
	}

	result.Duration = time.Since(start)
	return result
}

// verifyResource re-inspects the resource to detect state changes since planning.
// Returns exists=false when the resource is gone (caller skips it safely).
// On inspect error, returns conservative exists=true with original state — better to attempt deletion and fail
// than to silently skip a resource that might still exist.
// [SECURITY] TOCTOU defense — detect containers that became running between plan and sweep.
func (s *Sweeper) verifyResource(ctx context.Context, r *model.Resource) (exists bool, currentState string) {
	switch r.Type {
	case model.TypeContainer:
		ok, state, err := s.client.InspectContainer(ctx, r.ID)
		if err != nil {
			s.logger.Warn("failed to re-verify container — assuming original state",
				"id", r.ID, "error", err)
			return true, r.State
		}
		return ok, state

	case model.TypeImage:
		ok, err := s.client.InspectImage(ctx, r.ID)
		if err != nil {
			s.logger.Warn("failed to re-verify image — assuming still exists",
				"id", r.ID, "error", err)
			return true, r.State
		}
		return ok, r.State

	case model.TypeVolume:
		ok, err := s.client.InspectVolume(ctx, r.Name)
		if err != nil {
			s.logger.Warn("failed to re-verify volume — assuming still exists",
				"name", r.Name, "error", err)
			return true, r.State
		}
		return ok, r.State

	case model.TypeNetwork:
		ok, err := s.client.InspectNetwork(ctx, r.ID)
		if err != nil {
			s.logger.Warn("failed to re-verify network — assuming still exists",
				"id", r.ID, "error", err)
			return true, r.State
		}
		return ok, r.State
	}

	return true, r.State
}

// deleteResource dispatches to the correct Docker removal call by resource type.
func (s *Sweeper) deleteResource(ctx context.Context, r *model.Resource) error {
	switch r.Type {
	case model.TypeContainer:
		return s.client.RemoveContainer(ctx, r.ID)
	case model.TypeImage:
		return s.client.RemoveImage(ctx, r.ID)
	case model.TypeVolume:
		// [SECURITY] Volumes use Name, not ID — volume ID equals name in Docker.
		return s.client.RemoveVolume(ctx, r.Name)
	case model.TypeNetwork:
		return s.client.RemoveNetwork(ctx, r.ID)
	default:
		return fmt.Errorf("unknown resource type: %s", r.Type)
	}
}

// hasProtectionLabel checks whether the resource carries the configured protection label.
// [SECURITY] Triple-check — safety net in case the policy engine or planner had a bug.
func (s *Sweeper) hasProtectionLabel(r *model.Resource) bool {
	if s.protectionLabel == "" || len(r.Labels) == 0 {
		return false
	}
	parts := strings.SplitN(s.protectionLabel, "=", 2)
	if len(parts) != 2 {
		return false
	}
	v, ok := r.Labels[parts[0]]
	return ok && v == parts[1]
}
