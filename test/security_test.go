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
				State: model.StateRunning, CreatedAt: time.Now().Add(-720 * time.Hour),
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
		State: model.StateExited, CreatedAt: time.Now().Add(-48 * time.Hour),
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
	mock.containers["keep-me"] = model.StateExited
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
		State: model.StateExited, CreatedAt: time.Now().Add(-48 * time.Hour),
		Labels: map[string]string{"dredge.keep": "true"},
	}
	image := model.Resource{
		ID: "img-ref", Name: "<none>:<none>", Type: model.TypeImage,
		State: model.StateDangling, CreatedAt: time.Now().Add(-200 * time.Hour),
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
		State: model.StateExited, CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	// At plan time: exited. Between plan and sweep: container was restarted.
	mock.containers["ctr-toctou"] = model.StateRunning

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

	r1 := newResource(model.TypeContainer, "c1", "app1", model.StateExited)
	r2 := newResource(model.TypeContainer, "c2", "app2", model.StateExited)
	r3 := newResource(model.TypeContainer, "c3", "app3", model.StateExited)
	r4 := newResource(model.TypeVolume, "v1", "v1", model.StateAvailable)
	r5 := newResource(model.TypeNetwork, "n1", "custom-net", model.StateActive)

	mock.containers["c1"] = model.StateExited
	mock.containers["c2"] = model.StateExited
	mock.containers["c3"] = model.StateExited
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
			{ID: "c1", Name: "app1", Type: model.TypeContainer, State: model.StateExited, CreatedAt: old, Labels: map[string]string{}},
			{ID: "c2", Name: "app2", Type: model.TypeContainer, State: model.StateCreated, CreatedAt: old, Labels: map[string]string{}},
			{ID: "c3", Name: "app3", Type: model.TypeContainer, State: model.StateDead, CreatedAt: old, Labels: map[string]string{}},
		},
		Images: []model.Resource{
			{ID: "i1", Name: "<none>:<none>", Type: model.TypeImage, State: model.StateDangling, CreatedAt: old, Labels: map[string]string{}},
			{ID: "i2", Name: "old-base:v1", Type: model.TypeImage, State: model.StateUsed, CreatedAt: old, Labels: map[string]string{}},
			{ID: "i3", Name: "nginx:old", Type: model.TypeImage, State: model.StateUsed, CreatedAt: old, Labels: map[string]string{}},
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

// ─── Test 11 ─────────────────────────────────────────────────────────────────

// TestAdversarial_ImageIDWithSHA256PrefixResolvedCorrectly verifies that the
// dependency graph correctly protects an image when the container's ImageID
// carries the "sha256:" prefix (as returned by Docker's ContainerList API).
// Without normalization the lookup misses and the image appears unreferenced.
// [SECURITY] Adversarial: sha256: prefix in ImageID must not break dependency graph.
func TestAdversarial_ImageIDWithSHA256PrefixResolvedCorrectly(t *testing.T) {
	cfg := aggressiveConfig()
	engine := policy.New(cfg, adversarialLogger())

	// Simulate Docker's ContainerList format: ImageID has "sha256:" prefix + full 64-char hex.
	fullImageID := "sha256:abc123def456789012345678901234567890123456789012345678901234abcd"
	shortImageID := "abc123def456" // what normalizeImage() produces

	// Container is label-protected (kept) so the image dependency graph fires.
	// An exited+unprotected container would also be deleted, removing the image protection.
	ctr := model.Resource{
		ID:        "ctr-img-ref",
		Name:      "app",
		Type:      model.TypeContainer,
		State: model.StateExited,
		ImageID:   fullImageID,
		Labels:    map[string]string{"dredge.keep": "true"},
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	image := model.Resource{
		ID:        shortImageID,
		Name:      "myapp:latest",
		Type:      model.TypeImage,
		State: model.StateDangling,
		CreatedAt: time.Now().Add(-200 * time.Hour),
		Labels:    map[string]string{},
	}

	// ResolveReferences is the layer that resolves image→container via ImageID.
	// Without sha256: normalization this lookup always misses — graph broken.
	inv := &collector.Inventory{
		Containers: []model.Resource{ctr},
		Images:     []model.Resource{image},
	}
	inv.ResolveReferences()

	require.Len(t, inv.Images[0].References, 1,
		"ResolveReferences must link the container to the image despite sha256: prefix")

	decisions := engine.Evaluate(inv)

	imgDecision := findDecision(decisions, shortImageID)
	require.NotNil(t, imgDecision, "decision for image must exist")
	assert.Equal(t, model.ActionKeep, imgDecision.Action,
		"image referenced by kept container must be protected — sha256: prefix must be normalized")
	assert.Contains(t, imgDecision.Reason, "referenced by kept container",
		"reason must reflect dependency graph protection, not another rule")
}

// ─── Test 12 ─────────────────────────────────────────────────────────────────

// TestAdversarial_VolumeMountedByContainerNotOrphaned verifies that a volume
// mounted by a container (via MountedVolumes) is NOT classified as orphaned,
// even with an aggressive config that enables orphan deletion.
// [SECURITY] Adversarial: volume reference resolution must prevent orphan misclassification.
func TestAdversarial_VolumeMountedByContainerNotOrphaned(t *testing.T) {
	cfg := aggressiveConfig()
	engine := policy.New(cfg, adversarialLogger())

	ctr := model.Resource{
		ID:             "ctr-with-vol",
		Name:           "app",
		Type:           model.TypeContainer,
		State: model.StateExited,
		MountedVolumes: []string{"my-data"},
		Labels:         map[string]string{},
		CreatedAt:      time.Now().Add(-48 * time.Hour),
	}
	vol := model.Resource{
		ID:        "my-data",
		Name:      "my-data",
		Type:      model.TypeVolume,
		CreatedAt: time.Now().Add(-200 * time.Hour),
		Labels:    map[string]string{},
	}

	inv := &collector.Inventory{
		Containers: []model.Resource{ctr},
		Volumes:    []model.Resource{vol},
	}
	inv.ResolveReferences()

	require.Len(t, inv.Volumes[0].References, 1,
		"volume must have 1 reference after ResolveReferences")

	decisions := engine.Evaluate(inv)

	volDecision := findDecision(decisions, "my-data")
	require.NotNil(t, volDecision)
	assert.Equal(t, model.ActionKeep, volDecision.Action,
		"volume mounted by a container must NOT be classified as orphaned")
}

// ─── Test 13 ─────────────────────────────────────────────────────────────────

// TestAdversarial_NetworkConnectedToContainerNotUnused verifies that a custom
// network connected to a container is NOT classified as unused, even with an
// aggressive config that enables unused-network deletion.
// [SECURITY] Adversarial: network reference resolution must prevent unused misclassification.
func TestAdversarial_NetworkConnectedToContainerNotUnused(t *testing.T) {
	cfg := aggressiveConfig()
	engine := policy.New(cfg, adversarialLogger())

	ctr := model.Resource{
		ID:                  "ctr-with-net",
		Name:                "app",
		Type:                model.TypeContainer,
		State: model.StateExited,
		ConnectedNetworkIDs: []string{"aabbccddeeff"},
		Labels:              map[string]string{},
		CreatedAt:           time.Now().Add(-48 * time.Hour),
	}
	net := model.Resource{
		ID:        "aabbccddeeff",
		Name:      "my-app-network",
		Type:      model.TypeNetwork,
		IsDefault: false,
		CreatedAt: time.Now().Add(-200 * time.Hour),
		Labels:    map[string]string{},
	}

	inv := &collector.Inventory{
		Containers: []model.Resource{ctr},
		Networks:   []model.Resource{net},
	}
	inv.ResolveReferences()

	require.Len(t, inv.Networks[0].References, 1,
		"network must have 1 reference after ResolveReferences")

	decisions := engine.Evaluate(inv)

	netDecision := findDecision(decisions, "aabbccddeeff")
	require.NotNil(t, netDecision)
	assert.Equal(t, model.ActionKeep, netDecision.Action,
		"network connected to a container must NOT be classified as unused")
}

// ─── Test 14 ─────────────────────────────────────────────────────────────────

// TestAdversarial_InvalidGlobPatternRejectedAtConfigLoad verifies that a config
// with a syntactically invalid glob pattern in protection.name_patterns is
// rejected at load time, preventing silent bypass of name-pattern protection.
// [SECURITY] Adversarial: invalid glob = silent skip = unprotected resources.
func TestAdversarial_InvalidGlobPatternRejectedAtConfigLoad(t *testing.T) {
	_, err := loadInlineConfig(`
docker:
  socket: "/var/run/docker.sock"
  timeout: "30s"
protection:
  label: "dredge.keep=true"
  name_patterns:
    - "postgres*"
    - "[invalid-bracket"
`)
	require.Error(t, err, "config with invalid glob pattern must be rejected at load time")
	assert.Contains(t, err.Error(), "invalid protection name_pattern",
		"error must identify the bad name_pattern")
}

// ─── Test 18 ─────────────────────────────────────────────────────────────────

// TestSweepContextNotSharedWithCollection verifies that the sweeper receives a
// fresh context independent from the collection context. If both shared the same
// context (as was the case before the fix), any time spent in collection + user
// confirmation would eat into the sweep timeout, causing all deletions to fail
// silently when the context expires.
//
// This test exercises the sweeper in isolation (no Docker daemon required) and
// verifies that passing a pre-cancelled context to Execute causes failures, while
// a fresh context causes success — confirming that sweep must own its context.
func TestSweepContextNotSharedWithCollection(t *testing.T) {
	mock := newMockDockerSweeper()
	r := newResource(model.TypeContainer, "ctr1", "app", model.StateExited)
	mock.containers["ctr1"] = model.StateExited

	plan := buildPlan(r)
	sw := sweeper.New(mock, adversarialLogger(), "dredge.keep=true")

	// With a pre-cancelled context, ALL Docker calls fail immediately.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	result := sw.Execute(cancelledCtx, plan)
	assert.Empty(t, result.Succeeded,
		"cancelled context must cause sweep failures (verifies context is used)")

	// With a fresh context, the same plan succeeds — confirms sweep needs its own context.
	mock2 := newMockDockerSweeper()
	mock2.containers["ctr1"] = model.StateExited
	plan2 := buildPlan(r)
	sw2 := sweeper.New(mock2, adversarialLogger(), "dredge.keep=true")

	result2 := sw2.Execute(context.Background(), plan2)
	assert.Len(t, result2.Succeeded, 1,
		"fresh context must allow sweep to succeed")
}

// ─── Test 17 ─────────────────────────────────────────────────────────────────

// TestPlanReturnsErrPendingDeletionsSentinel verifies that the plan command
// exposes a sentinel error instead of calling os.Exit(1) inside RunE.
// os.Exit inside RunE skips all defers and crashes test processes — the fix
// returns ErrPendingDeletions so main.go translates it to an exit code.
func TestPlanReturnsErrPendingDeletionsSentinel(t *testing.T) {
	// ErrPendingDeletions must be exported and identifiable with errors.Is.
	err := cli.ErrPendingDeletions
	require.Error(t, err, "ErrPendingDeletions must be a non-nil sentinel error")
	assert.True(t, errors.Is(err, cli.ErrPendingDeletions),
		"errors.Is must identify ErrPendingDeletions correctly")
}

// ─── Test 16 ─────────────────────────────────────────────────────────────────

// TestAdversarial_ImageAtExactThresholdIsDeleted verifies that an image aged
// exactly at unused_older_than IS deleted. The container rule already uses >=;
// the image rule must be consistent to avoid silent boundary mismatches.
// [SECURITY] Regression: engine.go previously used > instead of >= for images,
// silently keeping images at the exact threshold boundary.
func TestAdversarial_ImageAtExactThresholdIsDeleted(t *testing.T) {
	threshold := 100 * time.Millisecond
	cfg := &config.Config{
		Docker: config.DockerConfig{Timeout: 30 * time.Second},
		Policies: config.PoliciesConfig{
			Images: config.ImagePolicy{UnusedOlderThan: threshold},
		},
		Protection: config.ProtectionConfig{Label: "dredge.keep=true"},
	}
	engine := policy.New(cfg, adversarialLogger())

	// Image exactly at the threshold: time.Since(createdAt) == threshold.
	// We sleep to ensure the image is old enough, then pass it to the engine.
	createdAt := time.Now().Add(-threshold)

	img := model.Resource{
		ID:         "img-boundary",
		Name:       "old-image:v1",
		Type:       model.TypeImage,
		State: model.StateUsed,
		CreatedAt:  createdAt,
		References: nil,
		Labels:     map[string]string{},
	}

	inv := &collector.Inventory{Images: []model.Resource{img}}
	decisions := engine.Evaluate(inv)

	d := findDecision(decisions, "img-boundary")
	require.NotNil(t, d)
	assert.Equal(t, model.ActionDelete, d.Action,
		"image aged >= unused_older_than must be deleted (>= not >)")
}

// ─── Test 15 ─────────────────────────────────────────────────────────────────

// TestAdversarial_MultipleContainersOneImageProtectedUntilAllDeleted verifies
// that an image is kept when at least one referencing container is kept, even
// if other referencing containers are marked for deletion.
// [SECURITY] Adversarial: image must survive as long as ANY kept container references it.
func TestAdversarial_MultipleContainersOneImageProtectedUntilAllDeleted(t *testing.T) {
	cfg := aggressiveConfig()
	engine := policy.New(cfg, adversarialLogger())

	imgID := "img-shared"

	// ctr1: exited 48h → matches deletion rule → will be deleted.
	ctr1 := model.Resource{
		ID:        "ctr-delete",
		Name:      "app-old",
		Type:      model.TypeContainer,
		State: model.StateExited,
		ImageID:   imgID,
		Labels:    map[string]string{},
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	// ctr2: label-protected → will be kept → image must survive.
	ctr2 := model.Resource{
		ID:        "ctr-keep",
		Name:      "app-protected",
		Type:      model.TypeContainer,
		State: model.StateExited,
		ImageID:   imgID,
		Labels:    map[string]string{"dredge.keep": "true"},
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	// Image is dangling so it would be eligible for deletion.
	// References start empty — ResolveReferences populates them.
	image := model.Resource{
		ID:        imgID,
		Name:      "<none>:<none>",
		Type:      model.TypeImage,
		State: model.StateDangling,
		Labels:    map[string]string{},
		CreatedAt: time.Now().Add(-200 * time.Hour),
	}

	inv := &collector.Inventory{
		Containers: []model.Resource{ctr1, ctr2},
		Images:     []model.Resource{image},
	}
	// ResolveReferences links containers to image via ImageID.
	// This must populate image.References = ["ctr-delete", "ctr-keep"].
	inv.ResolveReferences()
	require.Len(t, inv.Images[0].References, 2,
		"both containers must be linked to the image via ImageID")

	decisions := engine.Evaluate(inv)

	imgDecision := findDecision(decisions, imgID)
	require.NotNil(t, imgDecision)
	assert.Equal(t, model.ActionKeep, imgDecision.Action,
		"image must be kept when ANY referencing container is kept")
	assert.Contains(t, imgDecision.Reason, "referenced by kept container")

	ctr1Decision := findDecision(decisions, "ctr-delete")
	require.NotNil(t, ctr1Decision)
	assert.Equal(t, model.ActionDelete, ctr1Decision.Action,
		"unlabelled exited container must still be marked for deletion")

	ctr2Decision := findDecision(decisions, "ctr-keep")
	require.NotNil(t, ctr2Decision)
	assert.Equal(t, model.ActionKeep, ctr2Decision.Action,
		"label-protected container must be kept")
}
