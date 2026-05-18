package model

import (
	"strings"
	"time"
)

// ResourceType identifies the kind of Docker resource.
type ResourceType string

const (
	TypeContainer ResourceType = "container"
	TypeImage     ResourceType = "image"
	TypeVolume    ResourceType = "volume"
	TypeNetwork   ResourceType = "network"
)

// ResourceState is the normalized lifecycle state of a Docker resource.
// Using a named type prevents silent mismatches from raw string comparisons
// across Docker SDK version differences (e.g. "Exited" vs "exited").
type ResourceState string

const (
	// Container states (from Docker daemon, normalized to lowercase).
	StateRunning  ResourceState = "running"
	StateExited   ResourceState = "exited"
	StateCreated  ResourceState = "created"
	StateDead     ResourceState = "dead"
	StatePaused   ResourceState = "paused"
	StateRestart  ResourceState = "restarting"
	StateRemoving ResourceState = "removing"

	// Image states.
	StateDangling ResourceState = "dangling"
	StateUsed     ResourceState = "used"

	// Volume states.
	StateAvailable ResourceState = "available"

	// Network states.
	StateActive ResourceState = "active"
)

// Resource is the normalized representation of any Docker resource.
// All four resource types are flattened into this struct so the policy engine
// can evaluate them uniformly.
type Resource struct {
	// ID is the short (12-char) identifier for the resource.
	ID string
	// Name is the human-readable name. For containers, the "/" prefix is stripped.
	Name string
	// Type discriminates container/image/volume/network.
	Type ResourceType
	// State holds the normalized Docker lifecycle state.
	// [SECURITY] Typed to prevent silent mismatches from raw string comparisons.
	State ResourceState
	// CreatedAt is when Docker created the resource.
	CreatedAt time.Time
	// Size in bytes. Zero if unknown (volumes, networks).
	Size int64
	// Labels are the Docker labels attached to this resource.
	Labels map[string]string
	// ImageID is the image the container runs. Set only for containers.
	ImageID string
	// References holds IDs of containers that reference this resource.
	// Set for images (containers using them) and volumes/networks (containers mounting/connecting).
	// [SECURITY] Populated by ResolveReferences — foundation of the dependency graph.
	References []string
	// IsDefault marks the built-in Docker networks (bridge, host, none).
	// [SECURITY] Default networks are infrastructure — never deleted.
	IsDefault bool
	// MountedVolumes holds the names of named volumes this container mounts.
	// Set only for TypeContainer resources; used by ResolveReferences to populate volume References.
	MountedVolumes []string
	// ConnectedNetworkIDs holds the short (12-char) IDs of networks this container is connected to.
	// Set only for TypeContainer resources; used by ResolveReferences to populate network References.
	ConnectedNetworkIDs []string
}

// Action is the policy engine verdict for a resource.
type Action string

const (
	ActionKeep   Action = "keep"
	ActionDelete Action = "delete"
)

// Decision is the full verdict the policy engine emits for one resource.
type Decision struct {
	// Resource is the evaluated resource.
	Resource *Resource
	// Action is keep or delete.
	Action Action
	// Reason is a human-readable explanation.
	Reason string
	// RuleMatch names the rule that triggered the decision (useful for debug).
	RuleMatch string
}

// ExecutionPlan is the ordered list of deletions the planner produces.
type ExecutionPlan struct {
	// Deletions is sorted: containers → images → volumes → networks, oldest first within each type.
	// [SECURITY] Strict ordering prevents cascade failures and dangling references.
	Deletions []Deletion
	// TotalSize is the sum of sizes of all resources to be deleted (recoverable space).
	TotalSize int64
	// ProtectedCount is how many resources were evaluated but kept.
	ProtectedCount int
	// Timestamp records when the plan was generated.
	Timestamp time.Time
}

// Deletion is one item in an ExecutionPlan.
type Deletion struct {
	// Resource is the resource to delete.
	Resource *Resource
	// Reason is the human-readable deletion rationale.
	Reason string
	// Order is the position in the execution sequence (1-based).
	Order int
}

// SweepResult summarises what happened after sweep execution.
type SweepResult struct {
	// Succeeded lists deletions that completed without error.
	Succeeded []Deletion
	// Failed lists deletions that errored. Sweep continues after each failure (fail-forward).
	// [SECURITY] Fail-forward: one deletion failure must not abort the entire sweep.
	Failed []DeletionError
	// Plan is the original execution plan for comparison.
	Plan *ExecutionPlan
	// Duration is total sweep wall-clock time.
	Duration time.Duration
}

// DeletionError pairs a failed Deletion with its error message.
type DeletionError struct {
	Deletion Deletion
	Error    string
}

// MatchesProtectionLabel reports whether labels contains the configured protection label.
// label must be "key=value" (guaranteed by config validation). Returns false when either
// argument is empty or the format is unexpected.
// [SECURITY] Single implementation shared by all three defense-in-depth call sites
// (policy engine, planner, sweeper) — parsing bug fixed in one place.
func MatchesProtectionLabel(label string, labels map[string]string) bool {
	if label == "" || len(labels) == 0 {
		return false
	}
	parts := strings.SplitN(label, "=", 2)
	if len(parts) != 2 {
		return false
	}
	v, ok := labels[parts[0]]
	return ok && v == parts[1]
}
