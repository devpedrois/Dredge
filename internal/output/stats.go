package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/dustin/go-humanize"
	"github.com/user/dredge/internal/stats"
)

// FormatStatsTable writes a human-readable resource usage table to w.
func FormatStatsTable(s *stats.ResourceStats, w io.Writer) {
	fmt.Fprintln(w, "\nDocker Resource Usage")
	fmt.Fprintln(w, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Fprintf(w, "Containers:  %d total (%d running, %d exited, %d created, %d dead)\n",
		s.Containers.Total, s.Containers.Running, s.Containers.Exited,
		s.Containers.Created, s.Containers.Dead)
	fmt.Fprintf(w, "Images:      %d total (%d dangling, %d tagged)\n",
		s.Images.Total, s.Images.Dangling, s.Images.Tagged)
	fmt.Fprintf(w, "Volumes:     %d total\n", s.Volumes.Total)
	fmt.Fprintf(w, "Networks:    %d total (%d default, %d custom)\n",
		s.Networks.Total, s.Networks.Default, s.Networks.Custom)
	fmt.Fprintln(w, "\nDisk Usage:")
	fmt.Fprintf(w, "  Images:     %s\n", humanize.Bytes(uint64(s.DiskUsage.Images)))
	fmt.Fprintf(w, "  Containers: %s\n", humanize.Bytes(uint64(s.DiskUsage.Containers)))
	fmt.Fprintf(w, "  Volumes:    %s\n", humanize.Bytes(uint64(s.DiskUsage.Volumes)))
	fmt.Fprintf(w, "  Total:      %s\n", humanize.Bytes(uint64(s.DiskUsage.Total)))
}

// FormatStatsJSON writes stats as pretty-printed JSON to w.
func FormatStatsJSON(s *stats.ResourceStats, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
