package test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/user/dredge/internal/model"
	"github.com/user/dredge/internal/sweeper"
)

// mockDockerSweeper implements sweeper.DockerClient for unit tests.
type mockDockerSweeper struct {
	// containers maps container ID → current state (zero value = not found).
	containers map[string]model.ResourceState
	// images maps image ID → exists.
	images map[string]bool
	// volumes maps volume name → exists.
	volumes map[string]bool
	// networks maps network ID → exists.
	networks map[string]bool

	// removeErrors maps resource ID/name → error on remove.
	removeErrors map[string]error

	// removed records deletion order for ordering assertions.
	removed []string
}

func newMockDockerSweeper() *mockDockerSweeper {
	return &mockDockerSweeper{
		containers:   make(map[string]model.ResourceState),
		images:       make(map[string]bool),
		volumes:      make(map[string]bool),
		networks:     make(map[string]bool),
		removeErrors: make(map[string]error),
	}
}

func (m *mockDockerSweeper) RemoveContainer(ctx context.Context, id string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err, ok := m.removeErrors[id]; ok {
		return err
	}
	m.removed = append(m.removed, "container:"+id)
	delete(m.containers, id)
	return nil
}

func (m *mockDockerSweeper) RemoveImage(ctx context.Context, id string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err, ok := m.removeErrors[id]; ok {
		return err
	}
	m.removed = append(m.removed, "image:"+id)
	delete(m.images, id)
	return nil
}

func (m *mockDockerSweeper) RemoveVolume(ctx context.Context, name string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err, ok := m.removeErrors[name]; ok {
		return err
	}
	m.removed = append(m.removed, "volume:"+name)
	delete(m.volumes, name)
	return nil
}

func (m *mockDockerSweeper) RemoveNetwork(ctx context.Context, id string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err, ok := m.removeErrors[id]; ok {
		return err
	}
	m.removed = append(m.removed, "network:"+id)
	delete(m.networks, id)
	return nil
}

func (m *mockDockerSweeper) InspectContainer(ctx context.Context, id string) (bool, model.ResourceState, error) {
	if ctx.Err() != nil {
		return false, "", ctx.Err()
	}
	state, ok := m.containers[id]
	if !ok {
		return false, "", nil
	}
	return true, state, nil
}

func (m *mockDockerSweeper) InspectImage(ctx context.Context, id string) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	return m.images[id], nil
}

func (m *mockDockerSweeper) InspectVolume(ctx context.Context, name string) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	return m.volumes[name], nil
}

func (m *mockDockerSweeper) InspectNetwork(ctx context.Context, id string) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	return m.networks[id], nil
}

func newSweeperLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(new(bytes.Buffer), nil))
}

func newResource(rtype model.ResourceType, id, name string, state model.ResourceState) *model.Resource {
	return &model.Resource{
		ID:        id,
		Name:      name,
		Type:      rtype,
		State:     state,
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}
}

// buildPlan constructs an ExecutionPlan from a list of resources.
func buildPlan(resources ...*model.Resource) *model.ExecutionPlan {
	deletions := make([]model.Deletion, len(resources))
	for i, r := range resources {
		deletions[i] = model.Deletion{Resource: r, Reason: "test rule", Order: i + 1}
	}
	return &model.ExecutionPlan{Deletions: deletions, Timestamp: time.Now()}
}

// TestSweepDeletesResourcesInOrder verifies the plan order is honoured:
// container must be deleted before image.
// [SECURITY] Deletion order: containers before images.
func TestSweepDeletesResourcesInOrder(t *testing.T) {
	mock := newMockDockerSweeper()

	ctr := newResource(model.TypeContainer, "ctr1", "app", model.StateExited)
	img := newResource(model.TypeImage, "img1", "myimage:latest", model.StateDangling)

	mock.containers["ctr1"] = model.StateExited
	mock.images["img1"] = true

	plan := buildPlan(ctr, img)
	sw := sweeper.New(mock, newSweeperLogger(), "dredge.keep=true")
	result := sw.Execute(context.Background(), plan)

	require.Len(t, result.Succeeded, 2)
	require.Empty(t, result.Failed)

	assert.Equal(t, "container:ctr1", mock.removed[0])
	assert.Equal(t, "image:img1", mock.removed[1])
}

// TestSweepFailForward verifies that a deletion error on one item does not
// abort the sweep — subsequent items are still deleted.
// [SECURITY] Fail-forward — one failure must not abort the entire sweep.
func TestSweepFailForward(t *testing.T) {
	mock := newMockDockerSweeper()

	r1 := newResource(model.TypeContainer, "ctr1", "app1", model.StateExited)
	r2 := newResource(model.TypeContainer, "ctr2", "app2", model.StateExited)
	r3 := newResource(model.TypeVolume, "vol1", "vol1", model.StateAvailable)
	r4 := newResource(model.TypeNetwork, "net1", "custom", model.StateActive)

	mock.containers["ctr1"] = model.StateExited
	mock.containers["ctr2"] = model.StateExited
	mock.volumes["vol1"] = true
	mock.networks["net1"] = true

	mock.removeErrors["ctr2"] = errors.New("resource busy")

	plan := buildPlan(r1, r2, r3, r4)
	sw := sweeper.New(mock, newSweeperLogger(), "dredge.keep=true")
	result := sw.Execute(context.Background(), plan)

	assert.Len(t, result.Succeeded, 3, "ctr1, vol1, net1 should succeed")
	assert.Len(t, result.Failed, 1, "ctr2 should fail")
	assert.Equal(t, "ctr2", result.Failed[0].Deletion.Resource.ID)

	assert.Contains(t, mock.removed, "volume:vol1")
	assert.Contains(t, mock.removed, "network:net1")
}

// TestSweepSkipsVanishedResource verifies a resource gone before deletion is
// silently skipped without counting as an error.
func TestSweepSkipsVanishedResource(t *testing.T) {
	mock := newMockDockerSweeper()

	r := newResource(model.TypeContainer, "ctr1", "app", model.StateExited)
	// NOT added to mock.containers — simulates container gone between plan and sweep.

	plan := buildPlan(r)
	sw := sweeper.New(mock, newSweeperLogger(), "dredge.keep=true")
	result := sw.Execute(context.Background(), plan)

	assert.Empty(t, result.Succeeded)
	assert.Empty(t, result.Failed)
	assert.Empty(t, mock.removed)
}

// TestSweepSkipsContainerThatBecameRunning verifies TOCTOU defense:
// a container that started between plan and sweep is never touched.
// [SECURITY] TOCTOU: container may start between plan and sweep.
func TestSweepSkipsContainerThatBecameRunning(t *testing.T) {
	mock := newMockDockerSweeper()

	r := newResource(model.TypeContainer, "ctr1", "app", model.StateExited)
	mock.containers["ctr1"] = model.StateRunning // state changed after plan was built

	plan := buildPlan(r)
	sw := sweeper.New(mock, newSweeperLogger(), "dredge.keep=true")
	result := sw.Execute(context.Background(), plan)

	assert.Empty(t, result.Succeeded)
	assert.Empty(t, result.Failed)
	assert.Empty(t, mock.removed, "running container must never be deleted")
}

// TestSweepTripleChecksProtectionLabel verifies the sweeper safety net:
// a protected resource that somehow reaches the sweeper is rejected.
// [SECURITY] Triple-check: label verified at policy, planner, AND sweeper.
func TestSweepTripleChecksProtectionLabel(t *testing.T) {
	mock := newMockDockerSweeper()

	r := newResource(model.TypeContainer, "ctr1", "app", model.StateExited)
	r.Labels = map[string]string{"dredge.keep": "true"}
	mock.containers["ctr1"] = model.StateExited

	plan := buildPlan(r)
	sw := sweeper.New(mock, newSweeperLogger(), "dredge.keep=true")
	result := sw.Execute(context.Background(), plan)

	assert.Empty(t, result.Succeeded, "protected resource must not be deleted")
	assert.Empty(t, result.Failed)
	assert.Empty(t, mock.removed)
}

// TestSweepAuditLogsEveryDeletion verifies that each deletion produces a log entry
// containing resource identifiers.
func TestSweepAuditLogsEveryDeletion(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	mock := newMockDockerSweeper()
	r1 := newResource(model.TypeContainer, "ctr1", "app", model.StateExited)
	r2 := newResource(model.TypeImage, "img1", "old:latest", model.StateDangling)
	mock.containers["ctr1"] = model.StateExited
	mock.images["img1"] = true

	plan := buildPlan(r1, r2)
	sw := sweeper.New(mock, logger, "dredge.keep=true")
	result := sw.Execute(context.Background(), plan)

	require.Len(t, result.Succeeded, 2)

	logs := buf.String()
	assert.Contains(t, logs, "resource deleted")
	assert.Contains(t, logs, "ctr1")
	assert.Contains(t, logs, "img1")
}

// TestSweepResultCountsCorrect verifies Succeeded and Failed counts are accurate.
func TestSweepResultCountsCorrect(t *testing.T) {
	mock := newMockDockerSweeper()

	r1 := newResource(model.TypeContainer, "c1", "app1", model.StateExited)
	r2 := newResource(model.TypeContainer, "c2", "app2", model.StateExited)
	r3 := newResource(model.TypeContainer, "c3", "app3", model.StateExited)
	r4 := newResource(model.TypeImage, "i1", "img:latest", model.StateDangling)

	mock.containers["c1"] = model.StateExited
	mock.containers["c2"] = model.StateExited
	mock.containers["c3"] = model.StateExited
	mock.images["i1"] = true

	mock.removeErrors["c3"] = errors.New("conflict")

	plan := buildPlan(r1, r2, r3, r4)
	sw := sweeper.New(mock, newSweeperLogger(), "dredge.keep=true")
	result := sw.Execute(context.Background(), plan)

	assert.Len(t, result.Succeeded, 3)
	assert.Len(t, result.Failed, 1)
}

// TestSweepSkipsEmptyIDResource verifies that resources with empty IDs are silently
// skipped — they indicate a Docker API anomaly and must never trigger deletion.
// [SECURITY] Empty ID = malformed resource — never attempt deletion.
func TestSweepSkipsEmptyIDResource(t *testing.T) {
	mock := newMockDockerSweeper()

	r := &model.Resource{
		ID: "", Name: "mystery", Type: model.TypeContainer, State: model.StateExited,
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	plan := buildPlan(r)
	sw := sweeper.New(mock, newSweeperLogger(), "dredge.keep=true")
	result := sw.Execute(context.Background(), plan)

	assert.Empty(t, result.Succeeded)
	assert.Empty(t, result.Failed, "empty-ID resource must not count as failure")
	assert.Empty(t, mock.removed)
}

// TestSweepSkipsEmptyNameVolume verifies that a volume with an empty name is skipped.
// [SECURITY] Empty volume name = malformed resource — never attempt deletion.
func TestSweepSkipsEmptyNameVolume(t *testing.T) {
	mock := newMockDockerSweeper()

	r := &model.Resource{
		ID: "", Name: "", Type: model.TypeVolume, State: model.StateAvailable,
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	plan := buildPlan(r)
	sw := sweeper.New(mock, newSweeperLogger(), "dredge.keep=true")
	result := sw.Execute(context.Background(), plan)

	assert.Empty(t, result.Succeeded)
	assert.Empty(t, result.Failed, "empty-name volume must not count as failure")
	assert.Empty(t, mock.removed)
}

// TestSweepVolumesUseNameNotID verifies volumes are deleted by Name, not ID.
// [SECURITY] Volumes use Name for deletion — must not use ID.
func TestSweepVolumesUseNameNotID(t *testing.T) {
	mock := newMockDockerSweeper()

	vol := newResource(model.TypeVolume, "my-data-volume", "my-data-volume", model.StateAvailable)
	mock.volumes["my-data-volume"] = true

	plan := buildPlan(vol)
	sw := sweeper.New(mock, newSweeperLogger(), "dredge.keep=true")
	result := sw.Execute(context.Background(), plan)

	require.Len(t, result.Succeeded, 1)
	assert.Contains(t, mock.removed, "volume:my-data-volume")
}
