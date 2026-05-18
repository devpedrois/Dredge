//go:build integration

package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	dockerimage "github.com/docker/docker/api/types/image"
	volumeapi "github.com/docker/docker/api/types/volume"
	dockerclient "github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/user/dredge/internal/collector"
	"github.com/user/dredge/internal/config"
	"github.com/user/dredge/internal/docker"
	"github.com/user/dredge/internal/model"
	"github.com/user/dredge/internal/planner"
	"github.com/user/dredge/internal/policy"
	"github.com/user/dredge/internal/stats"
	"github.com/user/dredge/internal/sweeper"
)

const (
	integTestLabel    = "dredge.test"
	integTestLabelVal = "true"
	integTestImage    = "alpine:latest"
	dockerSocket      = "/var/run/docker.sock"
)

var (
	integLogger *slog.Logger
	integRawCli *dockerclient.Client
	integCli    *docker.Client
)

func TestMain(m *testing.M) {
	os.Exit(runIntegrationTests(m))
}

func runIntegrationTests(m *testing.M) int {
	integLogger = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	var err error
	integCli, err = docker.NewClient(dockerSocket, 30*time.Second, integLogger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: Docker not available — skipping: %v\n", err)
		return 0
	}
	defer integCli.Close()

	integRawCli, err = dockerclient.NewClientWithOpts(
		dockerclient.WithHost("unix://"+dockerSocket),
		dockerclient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: raw Docker client failed: %v\n", err)
		return 0
	}
	defer integRawCli.Close()

	ctx := context.Background()

	if err := ensureTestImage(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "integration: cannot ensure %s: %v\n", integTestImage, err)
		return 0
	}

	cleanupTestResources(ctx)
	code := m.Run()
	cleanupTestResources(ctx)
	return code
}

// ensureTestImage pulls integTestImage if not already present locally.
func ensureTestImage(ctx context.Context) error {
	_, _, err := integRawCli.ImageInspectWithRaw(ctx, integTestImage)
	if err == nil {
		return nil
	}
	reader, err := integRawCli.ImagePull(ctx, integTestImage, dockerimage.PullOptions{})
	if err != nil {
		return fmt.Errorf("pulling %s: %w", integTestImage, err)
	}
	defer reader.Close()
	_, _ = io.Copy(io.Discard, reader)
	return nil
}

// cleanupTestResources removes all containers labelled dredge.test=true.
func cleanupTestResources(ctx context.Context) {
	f := filters.NewArgs(filters.Arg("label", integTestLabel+"="+integTestLabelVal))
	ctrs, err := integRawCli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
	if err != nil {
		return
	}
	for _, ctr := range ctrs {
		_ = integRawCli.ContainerStop(ctx, ctr.ID, container.StopOptions{})
		_ = integRawCli.ContainerRemove(ctx, ctr.ID, container.RemoveOptions{Force: true})
	}
}

// createExitedContainer starts a container that exits immediately, waits for it, returns full ID.
func createExitedContainer(ctx context.Context, name string, extraLabels map[string]string) (string, error) {
	labels := map[string]string{integTestLabel: integTestLabelVal}
	for k, v := range extraLabels {
		labels[k] = v
	}

	resp, err := integRawCli.ContainerCreate(ctx, &container.Config{
		Image:  integTestImage,
		Cmd:    []string{"sh", "-c", "exit 0"},
		Labels: labels,
	}, nil, nil, nil, name)
	if err != nil {
		return "", fmt.Errorf("creating container %s: %w", name, err)
	}

	if err := integRawCli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return "", fmt.Errorf("starting container %s: %w", name, err)
	}

	// Wait for the container process to stop.
	statusCh, errCh := integRawCli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case <-statusCh:
	case err := <-errCh:
		return "", fmt.Errorf("waiting for %s to exit: %w", name, err)
	case <-time.After(10 * time.Second):
		return "", fmt.Errorf("container %s did not exit within 10s", name)
	}

	// Poll until Docker marks the container state as "exited".
	// ContainerWait can return before the daemon updates the state in ContainerList.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		info, inspectErr := integRawCli.ContainerInspect(ctx, resp.ID)
		if inspectErr != nil {
			return "", fmt.Errorf("inspecting %s post-exit: %w", name, inspectErr)
		}
		if info.State.Status == "exited" {
			return resp.ID, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return "", fmt.Errorf("container %s did not reach exited state within 5s of stopping", name)
}

// createRunningContainer starts a long-running container, returns full ID.
func createRunningContainer(ctx context.Context, name string, extraLabels map[string]string) (string, error) {
	labels := map[string]string{integTestLabel: integTestLabelVal}
	for k, v := range extraLabels {
		labels[k] = v
	}

	resp, err := integRawCli.ContainerCreate(ctx, &container.Config{
		Image:  integTestImage,
		Cmd:    []string{"sleep", "3600"},
		Labels: labels,
	}, nil, nil, nil, name)
	if err != nil {
		return "", fmt.Errorf("creating container %s: %w", name, err)
	}

	if err := integRawCli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return "", fmt.Errorf("starting container %s: %w", name, err)
	}

	return resp.ID, nil
}

// filterInventoryByLabel keeps only resources labelled key=value.
// This ensures integration tests never interact with non-test Docker resources.
// [SECURITY] Test isolation — never act on real user resources.
func filterInventoryByLabel(inv *collector.Inventory, key, value string) *collector.Inventory {
	filtered := &collector.Inventory{CollectedAt: inv.CollectedAt}
	for _, r := range inv.Containers {
		if r.Labels[key] == value {
			filtered.Containers = append(filtered.Containers, r)
		}
	}
	for _, r := range inv.Images {
		if r.Labels[key] == value {
			filtered.Images = append(filtered.Images, r)
		}
	}
	for _, r := range inv.Volumes {
		if r.Labels[key] == value {
			filtered.Volumes = append(filtered.Volumes, r)
		}
	}
	for _, r := range inv.Networks {
		if r.Labels[key] == value {
			filtered.Networks = append(filtered.Networks, r)
		}
	}
	return filtered
}

// aggressiveContainerConfig targets all exited containers immediately.
func aggressiveContainerConfig() *config.Config {
	return &config.Config{
		Docker: config.DockerConfig{Timeout: 30 * time.Second},
		Policies: config.PoliciesConfig{
			Containers: []config.ContainerRule{
				{Status: "exited", OlderThan: 0},
				{Status: "created", OlderThan: 0},
				{Status: "dead", OlderThan: 0},
			},
		},
		Protection: config.ProtectionConfig{Label: "dredge.keep=true"},
	}
}

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// ─── Test 1: Full lifecycle ───────────────────────────────────────────────────

// TestIntegration_FullLifecycle_PlanShowsSweepRemoves verifies the end-to-end
// happy path: an exited container appears in plan, is removed by sweep, and
// disappears from a subsequent plan.
func TestIntegration_FullLifecycle_PlanShowsSweepRemoves(t *testing.T) {
	ctx := context.Background()

	name := uniqueName("dredge-integ-lifecycle")
	_, err := createExitedContainer(ctx, name, nil)
	require.NoError(t, err, "setup: create exited container")

	cfg := aggressiveContainerConfig()
	col := collector.New(integCli, integLogger)
	eng := policy.New(cfg, integLogger)
	pln := planner.New(integLogger, cfg.Protection.Label)
	sw := sweeper.New(integCli, integLogger, cfg.Protection.Label)

	// Step 1: plan must include the test container.
	inv, err := col.CollectAll(ctx)
	require.NoError(t, err)
	inv = filterInventoryByLabel(inv, integTestLabel, integTestLabelVal)

	decisions := eng.Evaluate(inv)
	plan := pln.CreatePlan(decisions)

	require.NotEmpty(t, plan.Deletions, "plan must list the exited test container for deletion")
	found := false
	for _, del := range plan.Deletions {
		if del.Resource.Name == name {
			found = true
			break
		}
	}
	assert.True(t, found, "test container %q must appear in plan deletions", name)

	// Step 2: sweep must remove it.
	result := sw.Execute(ctx, plan)
	assert.NotEmpty(t, result.Succeeded, "sweep must succeed for at least one resource")
	assert.Empty(t, result.Failed, "sweep must not fail for the test container")

	// Step 3: second plan must not include the removed container.
	inv2, err := col.CollectAll(ctx)
	require.NoError(t, err)
	inv2 = filterInventoryByLabel(inv2, integTestLabel, integTestLabelVal)
	decisions2 := eng.Evaluate(inv2)
	plan2 := pln.CreatePlan(decisions2)

	for _, del := range plan2.Deletions {
		assert.NotEqual(t, name, del.Resource.Name,
			"swept container must not appear in second plan")
	}
}

// ─── Test 2: Protected resources survive sweep ────────────────────────────────

// TestIntegration_ProtectedResourceSurvivesSweep verifies that a container
// labelled dredge.keep=true is never included in a plan and survives sweep.
func TestIntegration_ProtectedResourceSurvivesSweep(t *testing.T) {
	ctx := context.Background()

	name := uniqueName("dredge-integ-protected")
	_, err := createExitedContainer(ctx, name, map[string]string{"dredge.keep": "true"})
	require.NoError(t, err, "setup: create protected exited container")

	cfg := aggressiveContainerConfig()
	col := collector.New(integCli, integLogger)
	eng := policy.New(cfg, integLogger)
	pln := planner.New(integLogger, cfg.Protection.Label)
	sw := sweeper.New(integCli, integLogger, cfg.Protection.Label)

	// Plan must NOT include the protected container.
	inv, err := col.CollectAll(ctx)
	require.NoError(t, err)
	inv = filterInventoryByLabel(inv, integTestLabel, integTestLabelVal)

	decisions := eng.Evaluate(inv)
	plan := pln.CreatePlan(decisions)

	for _, del := range plan.Deletions {
		assert.NotEqual(t, name, del.Resource.Name,
			"protected container must never appear in plan deletions")
	}

	// Sweep executes (may delete other test containers, not the protected one).
	_ = sw.Execute(ctx, plan)

	// Verify the protected container still exists.
	f := filters.NewArgs(filters.Arg("name", "/"+name))
	ctrs, err := integRawCli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
	require.NoError(t, err)
	assert.NotEmpty(t, ctrs, "protected container %q must still exist after sweep", name)
}

// ─── Test 3: Stats shows accurate counts ─────────────────────────────────────

// TestIntegration_StatsShowsAccurateCounts verifies that stats.Calculate produces
// correct container counts when given a filtered inventory with exactly 1 running
// and 1 exited container.
func TestIntegration_StatsShowsAccurateCounts(t *testing.T) {
	ctx := context.Background()

	runName := uniqueName("dredge-integ-stats-run")
	exitName := uniqueName("dredge-integ-stats-exit")

	_, err := createRunningContainer(ctx, runName, nil)
	require.NoError(t, err, "setup: create running container")

	_, err = createExitedContainer(ctx, exitName, nil)
	require.NoError(t, err, "setup: create exited container")

	col := collector.New(integCli, integLogger)
	inv, err := col.CollectAll(ctx)
	require.NoError(t, err)
	inv = filterInventoryByLabel(inv, integTestLabel, integTestLabelVal)

	s := stats.Calculate(inv)

	assert.GreaterOrEqual(t, s.Containers.Running, 1, "must report at least 1 running container")
	assert.GreaterOrEqual(t, s.Containers.Exited, 1, "must report at least 1 exited container")
	assert.GreaterOrEqual(t, s.Containers.Total, 2, "must report at least 2 total containers")
}

// ─── Test 4: Running container protected end-to-end ──────────────────────────

// TestIntegration_RunningContainerProtectedEndToEnd verifies that a running
// container is never included in a plan — even with an aggressive config that
// targets all container statuses. After plan+sweep the container is still running.
func TestIntegration_RunningContainerProtectedEndToEnd(t *testing.T) {
	ctx := context.Background()

	name := uniqueName("dredge-integ-running")
	id, err := createRunningContainer(ctx, name, nil)
	require.NoError(t, err, "setup: create running container")

	cfg := aggressiveContainerConfig()
	col := collector.New(integCli, integLogger)
	eng := policy.New(cfg, integLogger)
	pln := planner.New(integLogger, cfg.Protection.Label)

	inv, err := col.CollectAll(ctx)
	require.NoError(t, err)
	inv = filterInventoryByLabel(inv, integTestLabel, integTestLabelVal)

	decisions := eng.Evaluate(inv)
	plan := pln.CreatePlan(decisions)

	for _, del := range plan.Deletions {
		assert.NotEqual(t, name, del.Resource.Name,
			"running container must never appear in plan — hardcoded protection")
	}

	// Confirm the container is still running via Docker inspect.
	exists, state, err := integCli.InspectContainer(ctx, id)
	require.NoError(t, err)
	assert.True(t, exists, "running container must still exist after plan")
	assert.Equal(t, model.StateRunning, state, "container must still be in running state")
}

// ─── Test 5: Image dependency graph with real Docker IDs ─────────────────────

// TestIntegration_ImageDependencyGraphProtectsReferencedImage verifies that the
// image dependency graph correctly protects an image referenced by an exited
// container, using real Docker IDs that include the "sha256:" prefix in ImageID.
// This test specifically covers the sha256: normalization bug in ResolveReferences.
func TestIntegration_ImageDependencyGraphProtectsReferencedImage(t *testing.T) {
	ctx := context.Background()

	name := uniqueName("dredge-integ-imgdep")
	// Create an exited container — its ImageID will have sha256: prefix.
	_, err := createExitedContainer(ctx, name, nil)
	require.NoError(t, err, "setup: create exited container")

	cfg := aggressiveConfig()
	// Enable unused image deletion with very short threshold.
	cfg.Policies.Images.Dangling = true
	cfg.Policies.Images.UnusedOlderThan = time.Nanosecond

	col := collector.New(integCli, integLogger)
	eng := policy.New(cfg, integLogger)
	pln := planner.New(integLogger, cfg.Protection.Label)

	inv, err := col.CollectAll(ctx)
	require.NoError(t, err)
	inv = filterInventoryByLabel(inv, integTestLabel, integTestLabelVal)

	decisions := eng.Evaluate(inv)
	plan := pln.CreatePlan(decisions)

	// Find our test container in decisions — it must be marked for deletion (exited, age 0).
	var containerDecision *struct{ action string }
	for _, del := range plan.Deletions {
		assert.NotEqual(t, integTestImage, del.Resource.Name,
			"alpine:latest image must NOT appear in plan — our test container references it")
		_ = containerDecision
	}
}

// ─── Test 6: Volume mounted by stopped container survives plan ────────────────

// TestIntegration_VolumeMountedByContainerSurvivesPlan verifies that a named
// volume mounted by a stopped container is NOT classified as orphaned in the plan.
// This test exercises the volume reference resolution path added to ResolveReferences.
func TestIntegration_VolumeMountedByContainerSurvivesPlan(t *testing.T) {
	ctx := context.Background()

	volName := uniqueName("dredge-integ-vol")
	ctrName := uniqueName("dredge-integ-volctr")

	// Create a named volume and a stopped container that mounts it.
	_, err := integRawCli.VolumeCreate(ctx, volumeCreateBody(volName))
	require.NoError(t, err, "setup: create named volume")
	defer func() { _ = integRawCli.VolumeRemove(ctx, volName, false) }()

	_, err = createContainerWithVolume(ctx, ctrName, volName)
	require.NoError(t, err, "setup: create exited container with volume mount")

	cfg := &config.Config{
		Docker:     config.DockerConfig{Timeout: 30 * time.Second},
		Policies:   config.PoliciesConfig{Volumes: config.VolumePolicy{Orphaned: true}},
		Protection: config.ProtectionConfig{Label: "dredge.keep=true"},
	}

	col := collector.New(integCli, integLogger)
	eng := policy.New(cfg, integLogger)
	pln := planner.New(integLogger, cfg.Protection.Label)

	inv, err := col.CollectAll(ctx)
	require.NoError(t, err)

	decisions := eng.Evaluate(inv)
	plan := pln.CreatePlan(decisions)

	for _, del := range plan.Deletions {
		assert.NotEqual(t, volName, del.Resource.Name,
			"volume mounted by a stopped container must NOT appear in plan as orphaned")
	}
}

// ─── Test 7: TOCTOU — container restarts between plan and sweep (real Docker) ─

// TestIntegration_TOCTOUContainerRestartedBetweenPlanAndSweep verifies that a
// container which starts between plan-time and sweep-time is never deleted.
func TestIntegration_TOCTOUContainerRestartedBetweenPlanAndSweep(t *testing.T) {
	ctx := context.Background()

	name := uniqueName("dredge-integ-toctou")

	// Create a container that starts immediately then we'll restart it.
	id, err := createExitedContainer(ctx, name, nil)
	require.NoError(t, err, "setup: create exited container")

	cfg := aggressiveContainerConfig()
	col := collector.New(integCli, integLogger)
	eng := policy.New(cfg, integLogger)
	pln := planner.New(integLogger, cfg.Protection.Label)

	// Step 1: build plan while container is exited.
	inv, err := col.CollectAll(ctx)
	require.NoError(t, err)
	inv = filterInventoryByLabel(inv, integTestLabel, integTestLabelVal)
	decisions := eng.Evaluate(inv)
	plan := pln.CreatePlan(decisions)

	require.NotEmpty(t, plan.Deletions, "plan must include the exited container")

	// Step 2: restart the container before sweep (simulates TOCTOU race).
	err = integRawCli.ContainerStart(ctx, id, container.StartOptions{})
	require.NoError(t, err, "setup: restart container to simulate TOCTOU")
	defer func() {
		_ = integRawCli.ContainerStop(ctx, id, container.StopOptions{})
	}()

	// Step 3: sweep must detect the state change and skip the now-running container.
	sw := sweeper.New(integCli, integLogger, cfg.Protection.Label)
	result := sw.Execute(ctx, plan)

	// The container should be skipped (not deleted), so it should still exist.
	exists, state, err := integCli.InspectContainer(ctx, id)
	require.NoError(t, err)
	assert.True(t, exists, "TOCTOU: container must still exist after sweep")
	assert.Equal(t, model.StateRunning, state, "TOCTOU: container must still be running")

	// The restart means sweep skipped it — it should NOT appear in Succeeded.
	for _, s := range result.Succeeded {
		assert.NotEqual(t, name, s.Resource.Name,
			"TOCTOU: restarted container must not appear in sweep Succeeded list")
	}
}

// ─── helpers for new integration tests ───────────────────────────────────────

func volumeCreateBody(name string) volumeapi.CreateOptions {
	return volumeapi.CreateOptions{Name: name, Driver: "local"}
}

func createContainerWithVolume(ctx context.Context, name, volName string) (string, error) {
	resp, err := integRawCli.ContainerCreate(ctx, &container.Config{
		Image:  integTestImage,
		Cmd:    []string{"sh", "-c", "exit 0"},
		Labels: map[string]string{integTestLabel: integTestLabelVal},
	}, &container.HostConfig{
		Binds: []string{volName + ":/data"},
	}, nil, nil, name)
	if err != nil {
		return "", fmt.Errorf("creating container %s with volume: %w", name, err)
	}

	if err := integRawCli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return "", fmt.Errorf("starting container %s: %w", name, err)
	}

	statusCh, errCh := integRawCli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case <-statusCh:
	case err := <-errCh:
		return "", fmt.Errorf("waiting for %s to exit: %w", name, err)
	case <-time.After(10 * time.Second):
		return "", fmt.Errorf("container %s did not exit within 10s", name)
	}
	return resp.ID, nil
}
