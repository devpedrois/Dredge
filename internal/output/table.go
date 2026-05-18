package output

import (
	"fmt"
	"io"
	"strconv"

	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/user/dredge/internal/model"
)

var (
	colorContainer = color.New(color.FgCyan).SprintFunc()
	colorImage     = color.New(color.FgYellow).SprintFunc()
	colorVolume    = color.New(color.FgMagenta).SprintFunc()
	colorNetwork   = color.New(color.FgGreen).SprintFunc()
)

func typeColor(rtype model.ResourceType) func(a ...interface{}) string {
	switch rtype {
	case model.TypeContainer:
		return colorContainer
	case model.TypeImage:
		return colorImage
	case model.TypeVolume:
		return colorVolume
	case model.TypeNetwork:
		return colorNetwork
	}
	return func(a ...interface{}) string { return fmt.Sprint(a...) }
}

// FormatPlanTable writes the execution plan as a human-readable table to w.
func FormatPlanTable(plan *model.ExecutionPlan, w io.Writer) {
	if len(plan.Deletions) == 0 {
		fmt.Fprintln(w, "Nothing to clean. Your Docker is tidy!")
		return
	}

	fmt.Fprintf(w, "\nDredge Execution Plan — %s\n", plan.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Will delete: %d resources | Space recoverable: %s | Protected: %d resources\n\n",
		len(plan.Deletions),
		humanize.Bytes(uint64(plan.TotalSize)),
		plan.ProtectedCount,
	)

	table := tablewriter.NewTable(w)
	table.Header([]string{"#", "Type", "Name/ID", "Size", "Reason"})

	for _, d := range plan.Deletions {
		col := typeColor(d.Resource.Type)
		sizeStr := humanize.Bytes(uint64(d.Resource.Size))
		if d.Resource.Size == 0 {
			sizeStr = "-"
		}
		row := []string{
			strconv.Itoa(d.Order),
			col(string(d.Resource.Type)),
			d.Resource.Name,
			sizeStr,
			d.Reason,
		}
		table.Append(row) //nolint:errcheck
	}

	table.Render() //nolint:errcheck

	fmt.Fprintf(w, "\nRun 'dredge sweep --yes' to execute this plan.\n")
}
