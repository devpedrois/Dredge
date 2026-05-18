package test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/user/dredge/internal/cli"
	"github.com/user/dredge/internal/collector"
	"github.com/user/dredge/internal/config"
	"github.com/user/dredge/internal/model"
	"github.com/user/dredge/internal/planner"
	"github.com/user/dredge/internal/policy"
	"github.com/user/dredge/internal/sweeper"
)

// aggressiveConfig returns a config that targets every non-running container status
// at age 0, plus all dangling/orphaned/unused resources — used to stress-test
// hardcoded protections against aggressive deletion rules.
func aggressiveConfig() *config.Config {
	return &config.Config{
		Docker: config.DockerConfig{Timeout: 30 * time.Second},
		Policies: config.PoliciesConfig{
			Containers: []config.ContainerRule{
				{Status: "exited", OlderThan: 0},
				{Status: "created", OlderThan: 0},
				{Status: "dead", OlderThan: 0},
			},
			Images:   config.ImagePolicy{Dangling: true, UnusedOlderThan: time.Nanosecond},
			Volumes:  config.VolumePolicy{Orphaned: true},
			Networks: config.NetworkPolicy{Unused: true},
		},
		Protection: config.ProtectionConfig{
			Label: "dredge.keep=true",
		},
	}
}

// emptyPolicyConfig returns a config with zero deletion rules — deny-by-default baseline.
func emptyPolicyConfig() *config.Config {
	return &config.Config{
		Docker: config.DockerConfig{Timeout: 30 * time.Second},
		Policies: config.PoliciesConfig{
			Containers: nil,
			Images:     config.ImagePolicy{Dangling: false, UnusedOlderThan: 0},
			Volumes:    config.VolumePolicy{Orphaned: false},
			Networks:   config.NetworkPolicy{Unused: false},
		},
		Protection: config.ProtectionConfig{
			Label: "dredge.keep=true",
		},
	}
}

// adversarialLogger returns a silent logger for adversarial tests.
func adversarialLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
}

// ─── Test 1 ───────────────────────────────────────────────────────────────────

// TestAdversarial_RunningContainerNeverDeleted verifies that a running container
// is ALWAYS protected regardless of aggressive deletion rules in config.
// [SECURITY] Adversarial: running container protection is hardcoded — not configurable.
func TestAdversarial_RunningContainerNeverDeleted(t *testing.T) {
	cfg := aggressiveConfig()
	engine := policy.New(cfg, adversarialLogger())

	inv := &collector.Inventory{
		Containers: []model.Resource{
			{
				ID: "run-adv", Name: "critical-app", Type: model.TypeContainer,
				State: "running", CreatedAt: time.Now().Add(-720 * time.Hour),
				Labels: map[string]string{},
			},
		},
	}

	decisions := engine.Evaluate(inv)
	d := findDecision(decisions, "run-adv")
	require.NotNil(t, d)
	assert.Equal(t, model.ActionKeep, d.Action,
		"running container must be kept — hardcoded protection must override all rules")
	assert.Contains(t, d.Reason, "running container")
}

// ─── Test 2 ───────────────────────────────────────────────────────────────────

// TestAdversarial_ProtectionLabelSurvivesAllLayers verifies that the protection
// label is enforced independently at all three layers: policy engine, planner,
// and sweeper — so a bug in any single layer is caught by the others.
// [SECURITY] Adversarial: label protection verified at 3 independent layers.
func TestAdversarial_ProtectionLabelSurvivesAllLayers(t *testing.T) {
	cfg := aggressiveConfig()
	label := "dredge.keep=true"

	protected := &model.Resource{
		ID: "keep-me", Name: "critical-db", Type: model.TypeContainer,
		State: "exited", CreatedAt: time.Now().Add(-48 * time.Hour),
		Labels: map[string]string{"dredge.keep": "true"},
	}

	// Layer 1: policy engine must mark as Keep.
	engine := policy.New(cfg, adversarialLogger())
	inv := &collector.Inventory{Containers: []model.Resource{*protected}}
	decisions := engine.Evaluate(inv)
	d := findDecision(decisions, "keep-me")
	require.NotNil(t, d)
	assert.Equal(t, model.ActionKeep, d.Action,
		"layer 1 (policy engine) must protect label")
	assert.Contains(t, d.Reason, "protected by label")

	// Layer 2: planner must reject it even if a forged ActionDelete slips through.
	// [SECURITY] Simulates policy engine bug — forged decision bypasses layer 1.
	forgedDelete := model.Decision{
		Resource: protected, Action: model.ActionDelete, Reason: "forged by attacker",
	}
	p := planner.New(adversarialLogger(), label)
	plan := p.CreatePlan([]model.Decision{forgedDelete})
	assert.Empty(t, plan.Deletions,
		"layer 2 (planner) must reject protected resource even with forged ActionDelete")
	assert.Equal(t, 1, plan.ProtectedCount)

	// Layer 3: sweeper must skip the resource even if it reached execution.
	// [SECURITY] Simulates both policy engine and planner bugs — final safety net.
	mock := newMockDockerSweeper()
	mock.containers["keep-me"] = "exited"
	deletion := model.Deletion{Resource: protected, Reason: "forged", Order: 1}
	plan2 := &model.ExecutionPlan{Deletions: []model.Deletion{deletion}}
	sw := sweeper.New(mock, adversarialLogger(), label)
	result := sw.Execute(context.Background(), plan2)
	assert.Empty(t, result.Succeeded,
		"layer 3 (sweeper) must reject protected resource as last safety net")
	assert.Empty(t, mock.removed)
}

// ─── Test 3 ───────────────────────────────────────────────────────────────────

// TestAdversarial_DependencyGraphPreventsOrphaning verifies that an image is
// protected when its referencing container is kept (e.g., by label protection).
// Deleting the image would break the container when it next starts.
// [SECURITY] Adversarial: dependency graph prevents image deletion when any container needs it.
func TestAdversarial_DependencyGraphPreventsOrphaning(t *testing.T) {
	cfg := aggressiveConfig()

	// Container is label-protected → will be kept.
	// Image is dangling and old → without graph protection, would be deleted.
	container := model.Resource{
		ID: "ctr-ref", Name: "protected-app", Type: model.TypeContainer,
		State: "exited", CreatedAt: time.Now().Add(-48 * time.Hour),
		Labels: map[string]string{"dredge.keep": "true"},
	}
	image := model.Resource{
		ID: "img-ref", Name: "<none>:<none>", Type: model.TypeImage,
		State: "dangling", CreatedAt: time.Now().Add(-200 * time.Hour),
		References: []string{"ctr-ref"},
		Labels:     map[string]string{},
	}

	engine := policy.New(cfg, adversarialLogger())
	inv := &collector.Inventory{
		Containers: []model.Resource{container},
		Images:     []model.Resource{image},
	}

	decisions := engine.Evaluate(inv)

	containerDecision := findDecision(decisions, "ctr-ref")
	require.NotNil(t, containerDecision)
	assert.Equal(t, model.ActionKeep, containerDecision.Action,
		"label-protected container must be kept")

	imageDecision := findDecision(decisions, "img-ref")
	require.NotNil(t, imageDecision)
	assert.Equal(t, model.ActionKeep, imageDecision.Action,
		"image referenced by kept container must be protected by dependency graph")
	assert.Contains(t, imageDecision.Reason, "referenced by kept container")
}

// ─── Test 4 ───────────────────────────────────────────────────────────────────

// TestAdversarial_TOCTOUContainerStartsBetweenPlanAndSweep verifies that a
// container that transitions to "running" between plan-time and sweep-time
// is never touched. This is the TOCTOU (time-of-check/time-of-use) defense.
// [SECURITY] Adversarial: TOCTOU defense — state changed between plan and execution.
func TestAdversarial_TOCTOUContainerStartsBetweenPlanAndSweep(t *testing.T) {
	mock := newMockDockerSweeper()

	r := &model.Resource{
		ID: "ctr-toctou", Name: "app", Type: model.TypeContainer,
		State: "exited", CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	// At plan time: exited. Between plan and sweep: container was restarted.
	mock.containers["ctr-toctou"] = "running"

	plan := buildPlan(r)
	sw := sweeper.New(mock, adversarialLogger(), "dredge.keep=true")
	result := sw.Execute(context.Background(), plan)

	assert.Empty(t, result.Succeeded,
		"TOCTOU: container now running must not be deleted")
	assert.Empty(t, result.Failed,
		"TOCTOU skip must not count as a deletion failure")
	assert.Empty(t, mock.removed,
		"running container must never appear in the removed list")
}

// ─── Test 5 ───────────────────────────────────────────────────────────────────

// TestAdversarial_ConfigWithRunningStatusRejected verifies that a config which
// attempts to target running containers is rejected at load time with a clear error.
// [SECURITY] Adversarial: config injection to target running containers must be blocked.
func TestAdversarial_ConfigWithRunningStatusRejected(t *testing.T) {
	_, err := loadInlineConfig(`
docker:
  socket: "/var/run/docker.sock"
  timeout: "30s"
policies:
  containers:
    - status: "running"
      older_than: "0s"
`)
	require.Error(t, err, "config with running status must be rejected at load time")
	assert.Contains(t, err.Error(), "running containers are always protected",
		"error must clearly state why running containers cannot be targeted")
}

// ─── Test 6 ───────────────────────────────────────────────────────────────────

// TestAdversarial_ConfigWithUnknownFieldsRejected verifies that a config with
// unrecognised fields fails immediately — typos and injected keys must never
// pass silently through config loading.
// [SECURITY] Adversarial: config injection via unknown fields must be blocked.
func TestAdversarial_ConfigWithUnknownFieldsRejected(t *testing.T) {
	_, err := loadInlineConfig(`
docker:
  socket: "/var/run/docker.sock"
  timeout: "30s"
hack_mode: true
bypass_protection: true
`)
	require.Error(t, err, "config with unknown fields must be rejected")
	assert.True(t,
		strings.Contains(err.Error(), "unknown") || strings.Contains(err.Error(), "invalid"),
		"error must mention the unknown/invalid field, got: %s", err.Error())
}

// ─── Test 7 ───────────────────────────────────────────────────────────────────

// TestAdversarial_DefaultNetworksNeverDeleted verifies that the built-in Docker
// networks (bridge, host, none) are always protected regardless of how aggressive
// the network cleanup policy is.
// [SECURITY] Adversarial: default Docker network protection is absolute.
func TestAdversarial_DefaultNetworksNeverDeleted(t *testing.T) {
	cfg := aggressiveConfig()
	engine := policy.New(cfg, adversarialLogger())

	inv := &collector.Inventory{
		Networks: []model.Resource{
			{ID: "net-bridge", Name: "bridge", Type: model.TypeNetwork, IsDefault: true, Labels: map[string]string{}},
			{ID: "net-host", Name: "host", Type: model.TypeNetwork, IsDefault: true, Labels: map[string]string{}},
			{ID: "net-none", Name: "none", Type: model.TypeNetwork, IsDefault: true, Labels: map[string]string{}},
			{ID: "net-custom", Name: "my-app-net", Type: model.TypeNetwork, IsDefault: false, References: nil, Labels: map[string]string{}},
		},
	}

	decisions := engine.Evaluate(inv)

	for _, id := range []string{"net-bridge", "net-host", "net-none"} {
		d := findDecision(decisions, id)
		require.NotNil(t, d, "decision for %s must exist", id)
		assert.Equal(t, model.ActionKeep, d.Action,
			"default network %q must always be protected", d.Resource.Name)
		assert.Contains(t, d.Reason, "default Docker network")
	}

	custom := findDecision(decisions, "net-custom")
	require.NotNil(t, custom)
	assert.Equal(t, model.ActionDelete, custom.Action,
		"unused custom network must be deleted when policy.unused=true")
}

// ─── Test 8 ───────────────────────────────────────────────────────────────────

// TestAdversarial_SweepFailForwardOnPartialFailure verifies that when items 2 and 4
// (out of 5) fail, the sweep continues and successfully deletes items 1, 3, 5.
// [SECURITY] Adversarial: partial failures must not abort the entire sweep.
func TestAdversarial_SweepFailForwardOnPartialFailure(t *testing.T) {
	mock := newMockDockerSweeper()

	r1 := newResource(model.TypeContainer, "c1", "app1", "exited")
	r2 := newResource(model.TypeContainer, "c2", "app2", "exited")
	r3 := newResource(model.TypeContainer, "c3", "app3", "exited")
	r4 := newResource(model.TypeVolume, "v1", "v1", "available")
	r5 := newResource(model.TypeNetwork, "n1", "custom-net", "active")

	mock.containers["c1"] = "exited"
	mock.containers["c2"] = "exited"
	mock.containers["c3"] = "exited"
	mock.volumes["v1"] = true // volume uses Name, not ID (Name == "v1" here)
	mock.networks["n1"] = true

	// Items 2 and 4 fail — sweep must continue with 3 and 5.
	mock.removeErrors["c2"] = errors.New("resource busy")
	mock.removeErrors["v1"] = errors.New("volume in use by another container")

	plan := buildPlan(r1, r2, r3, r4, r5)
	sw := sweeper.New(mock, adversarialLogger(), "dredge.keep=true")
	result := sw.Execute(context.Background(), plan)

	assert.Len(t, result.Succeeded, 3, "items c1, c3, n1 must succeed")
	assert.Len(t, result.Failed, 2, "items c2, v1 must fail")

	succeededIDs := make([]string, 0, len(result.Succeeded))
	for _, s := range result.Succeeded {
		succeededIDs = append(succeededIDs, s.Resource.ID)
	}
	assert.Contains(t, succeededIDs, "c1")
	assert.Contains(t, succeededIDs, "c3")
	assert.Contains(t, succeededIDs, "n1")

	failedIDs := make([]string, 0, len(result.Failed))
	for _, f := range result.Failed {
		failedIDs = append(failedIDs, f.Deletion.Resource.ID)
	}
	assert.Contains(t, failedIDs, "c2")
	assert.Contains(t, failedIDs, "v1")
}

// ─── Test 9 ───────────────────────────────────────────────────────────────────

// TestAdversarial_NonInteractiveSweepWithoutYesFails verifies that sweep running
// in a non-TTY context (e.g. piped into a script) without --yes returns a clear
// error rather than executing silently and deleting resources.
// [SECURITY] Adversarial: prevent accidental sweep via pipe.
func TestAdversarial_NonInteractiveSweepWithoutYesFails(t *testing.T) {
	// isTTY=false simulates piped stdin: echo "yes" | dredge sweep
	err := cli.CheckSweepConfirmation(false, false)
	require.Error(t, err, "non-interactive sweep without --yes must return an error")
	assert.Contains(t, err.Error(), "requires --yes flag for non-interactive execution")
}

// TestAdversarial_NonInteractiveSweepWithYesSucceeds verifies that --yes
// bypasses the TTY check regardless of terminal type.
// [SECURITY] --yes is the explicit opt-in for non-interactive automation.
func TestAdversarial_NonInteractiveSweepWithYesSucceeds(t *testing.T) {
	err := cli.CheckSweepConfirmation(true, false)
	assert.NoError(t, err, "--yes must allow non-interactive execution")
}

// TestAdversarial_InteractiveSweepWithoutYesProceeds verifies that a TTY present
// without --yes is allowed (the interactive prompt will be shown).
func TestAdversarial_InteractiveSweepWithoutYesProceeds(t *testing.T) {
	err := cli.CheckSweepConfirmation(false, true)
	assert.NoError(t, err, "TTY present must proceed to the interactive confirmation prompt")
}

// ─── Test 10 ──────────────────────────────────────────────────────────────────

// TestAdversarial_EmptyConfigDeletesNothing verifies the deny-by-default posture:
// when no deletion rules are configured, a full inventory of 10 resources of
// every type produces an empty plan — nothing is deleted.
// [SECURITY] Adversarial: deny-by-default — no rules means no deletions.
func TestAdversarial_EmptyConfigDeletesNothing(t *testing.T) {
	cfg := emptyPolicyConfig()
	engine := policy.New(cfg, adversarialLogger())

	old := time.Now().Add(-720 * time.Hour) // 30 days old — would trigger any rule

	inv := &collector.Inventory{
		Containers: []model.Resource{
			{ID: "c1", Name: "app1", Type: model.TypeContainer, State: "exited", CreatedAt: old, Labels: map[string]string{}},
			{ID: "c2", Name: "app2", Type: model.TypeContainer, State: "created", CreatedAt: old, Labels: map[string]string{}},
			{ID: "c3", Name: "app3", Type: model.TypeContainer, State: "dead", CreatedAt: old, Labels: map[string]string{}},
		},
		Images: []model.Resource{
			{ID: "i1", Name: "<none>:<none>", Type: model.TypeImage, State: "dangling", CreatedAt: old, Labels: map[string]string{}},
			{ID: "i2", Name: "old-base:v1", Type: model.TypeImage, State: "unused", CreatedAt: old, Labels: map[string]string{}},
			{ID: "i3", Name: "nginx:old", Type: model.TypeImage, State: "unused", CreatedAt: old, Labels: map[string]string{}},
		},
		Volumes: []model.Resource{
			{ID: "v1", Name: "orphan1", Type: model.TypeVolume, CreatedAt: old, Labels: map[string]string{}},
			{ID: "v2", Name: "orphan2", Type: model.TypeVolume, CreatedAt: old, Labels: map[string]string{}},
		},
		Networks: []model.Resource{
			{ID: "n1", Name: "unused-net", Type: model.TypeNetwork, IsDefault: false, CreatedAt: old, Labels: map[string]string{}},
			{ID: "n2", Name: "another-net", Type: model.TypeNetwork, IsDefault: false, CreatedAt: old, Labels: map[string]string{}},
		},
	}

	decisions := engine.Evaluate(inv)
	p := planner.New(adversarialLogger(), cfg.Protection.Label)
	plan := p.CreatePlan(decisions)

	assert.Empty(t, plan.Deletions,
		"empty config must produce empty plan — deny-by-default: got %d unexpected deletions", len(plan.Deletions))
	assert.Equal(t, 10, plan.ProtectedCount,
		"all 10 resources must be in ProtectedCount when no deletion rules exist")
	assert.Equal(t, int64(0), plan.TotalSize)
}
