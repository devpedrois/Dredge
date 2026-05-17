package test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/user/dredge/internal/collector"
	"github.com/user/dredge/internal/model"
)

// mockDockerClient is a test double implementing collector.DockerClient.
// [SECURITY] Interface enables unit testing without real Docker socket access.
type mockDockerClient struct {
	containers []model.Resource
	images     []model.Resource
	volumes    []model.Resource
	networks   []model.Resource
	listErr    error
}

func (m *mockDockerClient) ListContainers(_ context.Context) ([]model.Resource, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.containers, nil
}

func (m *mockDockerClient) ListImages(_ context.Context) ([]model.Resource, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.images, nil
}

func (m *mockDockerClient) ListVolumes(_ context.Context) ([]model.Resource, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.volumes, nil
}

func (m *mockDockerClient) ListNetworks(_ context.Context) ([]model.Resource, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.networks, nil
}

func (m *mockDockerClient) Ping(_ context.Context) error { return nil }
func (m *mockDockerClient) Close() error                 { return nil }

func newTestCollector(client collector.DockerClient) *collector.Collector {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return collector.New(client, logger)
}

var (
	containerA = model.Resource{
		ID:        "aaa111aaa111",
		Name:      "web-app",
		Type:      model.TypeContainer,
		State:     "exited",
		CreatedAt: time.Now().Add(-25 * time.Hour),
		Size:      1024,
		Labels:    map[string]string{"env": "prod"},
		ImageID:   "img111img111",
	}
	containerB = model.Resource{
		ID:        "bbb222bbb222",
		Name:      "worker",
		Type:      model.TypeContainer,
		State:     "running",
		CreatedAt: time.Now().Add(-1 * time.Hour),
		Labels:    map[string]string{},
		ImageID:   "img111img111",
	}
	containerC = model.Resource{
		ID:        "ccc333ccc333",
		Name:      "old-job",
		Type:      model.TypeContainer,
		State:     "dead",
		CreatedAt: time.Now().Add(-100 * time.Hour),
		Labels:    map[string]string{},
		ImageID:   "img222img222",
	}
	imageX = model.Resource{
		ID:    "img111img111",
		Name:  "nginx:latest",
		Type:  model.TypeImage,
		State: "used",
		Size:  50 * 1024 * 1024,
	}
	imageY = model.Resource{
		ID:    "img222img222",
		Name:  "<none>:<none>",
		Type:  model.TypeImage,
		State: "dangling",
		Size:  10 * 1024 * 1024,
	}
	volumeV = model.Resource{
		ID:   "my-volume",
		Name: "my-volume",
		Type: model.TypeVolume,
	}
	networkN = model.Resource{
		ID:        "net111net111",
		Name:      "my-net",
		Type:      model.TypeNetwork,
		IsDefault: false,
	}
)

func TestCollectAll_ReturnsInventoryWithAllTypes(t *testing.T) {
	mock := &mockDockerClient{
		containers: []model.Resource{containerA, containerB, containerC},
		images:     []model.Resource{imageX, imageY},
		volumes:    []model.Resource{volumeV},
		networks:   []model.Resource{networkN},
	}

	inv, err := newTestCollector(mock).CollectAll(context.Background())

	require.NoError(t, err)
	require.NotNil(t, inv)
	assert.Len(t, inv.Containers, 3)
	assert.Len(t, inv.Images, 2)
	assert.Len(t, inv.Volumes, 1)
	assert.Len(t, inv.Networks, 1)
	assert.False(t, inv.CollectedAt.IsZero())
}

func TestCollectAll_EmptyDockerReturnsEmptyInventory(t *testing.T) {
	mock := &mockDockerClient{}

	inv, err := newTestCollector(mock).CollectAll(context.Background())

	require.NoError(t, err)
	require.NotNil(t, inv)
	assert.Empty(t, inv.Containers)
	assert.Empty(t, inv.Images)
	assert.Empty(t, inv.Volumes)
	assert.Empty(t, inv.Networks)
}

func TestCollectAll_DockerErrorPropagated(t *testing.T) {
	mock := &mockDockerClient{listErr: errors.New("daemon unreachable")}

	inv, err := newTestCollector(mock).CollectAll(context.Background())

	require.Error(t, err)
	assert.Nil(t, inv)
	assert.Contains(t, err.Error(), "containers")
}

func TestInventory_ReferencesResolvedCorrectly(t *testing.T) {
	// containerA and containerB both reference imageX.
	// containerC references imageY.
	mock := &mockDockerClient{
		containers: []model.Resource{containerA, containerB, containerC},
		images:     []model.Resource{imageX, imageY},
	}

	inv, err := newTestCollector(mock).CollectAll(context.Background())

	require.NoError(t, err)
	var imgX, imgY *model.Resource
	for i := range inv.Images {
		switch inv.Images[i].ID {
		case "img111img111":
			imgX = &inv.Images[i]
		case "img222img222":
			imgY = &inv.Images[i]
		}
	}
	require.NotNil(t, imgX)
	require.NotNil(t, imgY)
	// [SECURITY] Dependency graph: both containers that use imgX must appear in References.
	assert.ElementsMatch(t, []string{"aaa111aaa111", "bbb222bbb222"}, imgX.References)
	assert.ElementsMatch(t, []string{"ccc333ccc333"}, imgY.References)
}

func TestDanglingImage_StateIsDangling(t *testing.T) {
	dangling := model.Resource{
		ID:    "ddd444ddd444",
		Name:  "<none>:<none>",
		Type:  model.TypeImage,
		State: "dangling",
	}
	mock := &mockDockerClient{
		images: []model.Resource{dangling},
	}

	inv, err := newTestCollector(mock).CollectAll(context.Background())

	require.NoError(t, err)
	require.Len(t, inv.Images, 1)
	assert.Equal(t, "dangling", inv.Images[0].State)
	assert.Equal(t, "<none>:<none>", inv.Images[0].Name)
}

func TestContainerMetadata_CapturedCorrectly(t *testing.T) {
	createdAt := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	ctr := model.Resource{
		ID:        "fff666fff666",
		Name:      "my-service",
		Type:      model.TypeContainer,
		State:     "exited",
		CreatedAt: createdAt,
		Size:      2048,
		Labels:    map[string]string{"team": "platform", "env": "staging"},
		ImageID:   "img333img333",
	}
	mock := &mockDockerClient{
		containers: []model.Resource{ctr},
	}

	inv, err := newTestCollector(mock).CollectAll(context.Background())

	require.NoError(t, err)
	require.Len(t, inv.Containers, 1)
	got := inv.Containers[0]
	assert.Equal(t, "fff666fff666", got.ID)
	assert.Equal(t, "my-service", got.Name)
	assert.Equal(t, model.TypeContainer, got.Type)
	assert.Equal(t, "exited", got.State)
	assert.Equal(t, createdAt, got.CreatedAt)
	assert.Equal(t, int64(2048), got.Size)
	assert.Equal(t, map[string]string{"team": "platform", "env": "staging"}, got.Labels)
	assert.Equal(t, "img333img333", got.ImageID)
}
