package policy

import "github.com/user/dredge/internal/model"

// ResolveGraph performs a second-pass over decisions to enforce the dependency
// graph rule: an image cannot be deleted if any of its referencing containers
// will be kept.
// [SECURITY] Dependency graph — image protected because a kept container needs it.
func ResolveGraph(decisions []model.Decision) []model.Decision {
	// Build the set of containers marked for deletion and a name lookup map.
	deletedContainers := make(map[string]bool, len(decisions))
	containerNames := make(map[string]string, len(decisions))

	for _, d := range decisions {
		if d.Resource.Type != model.TypeContainer {
			continue
		}
		containerNames[d.Resource.ID] = d.Resource.Name
		if d.Action == model.ActionDelete {
			deletedContainers[d.Resource.ID] = true
		}
	}

	// result is a shallow copy: Decision value fields (Action, Reason, RuleMatch) are
	// independent per element, but Resource pointers are shared with the input slice.
	// Callers must not mutate Resource fields via the returned slice.
	result := make([]model.Decision, len(decisions))
	copy(result, decisions)

	for i, d := range result {
		if d.Resource.Type != model.TypeImage || d.Action != model.ActionDelete {
			continue
		}
		// If any referencing container is NOT being deleted, protect the image.
		for _, cID := range d.Resource.References {
			if !deletedContainers[cID] {
				name := containerNames[cID]
				if name == "" {
					name = cID
				}
				result[i].Action = model.ActionKeep
				result[i].Reason = "referenced by kept container: " + name
				result[i].RuleMatch = ""
				break
			}
		}
	}

	return result
}
