package interop

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Report aggregates results across every vector in every loaded file.
type Report struct {
	Results []Result

	// Per-status counts (computed by Summarize).
	Pass    int
	Fail    int
	Skip    int
	Pending int
	Error   int
}

// Summarize fills the per-status counts from r.Results.
func (r *Report) Summarize() {
	r.Pass, r.Fail, r.Skip, r.Pending, r.Error = 0, 0, 0, 0, 0
	for _, res := range r.Results {
		switch res.Status {
		case StatusPass:
			r.Pass++
		case StatusFail:
			r.Fail++
		case StatusSkip:
			r.Skip++
		case StatusPending:
			r.Pending++
		case StatusError:
			r.Error++
		}
	}
}

// Total returns the count of all results regardless of status.
func (r *Report) Total() int {
	return len(r.Results)
}

// PendingByWorkstream returns counts of StatusPending results grouped by
// workstream label. Useful for showing which alignment workstream gap is
// blocking the most vectors.
func (r *Report) PendingByWorkstream() map[string]int {
	out := make(map[string]int)
	for _, res := range r.Results {
		if res.Status == StatusPending {
			out[res.Workstream]++
		}
	}
	return out
}

// Run executes every vector in every loaded VectorFile against the registry.
// Vectors with Skip=true become StatusSkip without dispatcher invocation.
// Vectors whose VectorFile.ID has no registered dispatcher become StatusPending.
func Run(ctx context.Context, files []*VectorFile, reg *Registry) Report {
	var report Report

	for _, file := range files {
		dispatcher := reg.Lookup(file.ID)
		for _, v := range file.Vectors {
			if v.Skip {
				report.Results = append(report.Results, Result{
					FileID:     file.ID,
					VectorID:   v.ID,
					Status:     StatusSkip,
					Message:    skipMessage(v),
					Workstream: workstreamForFile(file.ID),
				})
				continue
			}
			if dispatcher == nil {
				report.Results = append(report.Results, pendingResult(file, v))
				continue
			}
			res := safeRun(ctx, dispatcher, file, v)
			report.Results = append(report.Results, res)
		}
	}

	report.Summarize()
	return report
}

// safeRun wraps Dispatcher.Run in a panic recover so one misbehaving
// dispatcher cannot crash the whole runner.
func safeRun(ctx context.Context, d Dispatcher, file *VectorFile, v Vector) (out Result) {
	defer func() {
		if rec := recover(); rec != nil {
			out = Result{
				FileID:     file.ID,
				VectorID:   v.ID,
				Status:     StatusError,
				Message:    fmt.Sprintf("dispatcher panic: %v", rec),
				Workstream: workstreamForFile(file.ID),
			}
		}
	}()
	return d.Run(ctx, file, v)
}

func skipMessage(v Vector) string {
	if v.SkipReason != "" {
		return "vector marked skip: " + v.SkipReason
	}
	return "vector marked skip"
}

// FormatSummary writes a human-readable summary of the report to w.
// Output is stable across runs (sorted file IDs, sorted vector IDs).
func FormatSummary(w io.Writer, files []*VectorFile, report Report) {
	fmt.Fprintf(w, "=== Anvil Conformance Runner ===\n")
	fmt.Fprintf(w, "Files loaded: %d\n", len(files))
	fmt.Fprintf(w, "Total vectors: %d\n", report.Total())
	fmt.Fprintf(w, "  PASS:    %d\n", report.Pass)
	fmt.Fprintf(w, "  FAIL:    %d\n", report.Fail)
	fmt.Fprintf(w, "  SKIP:    %d\n", report.Skip)
	fmt.Fprintf(w, "  PENDING: %d\n", report.Pending)
	fmt.Fprintf(w, "  ERROR:   %d\n", report.Error)
	fmt.Fprintln(w)

	// Per-file breakdown.
	type fileRow struct {
		id    string
		count int
	}
	rows := make([]fileRow, 0, len(files))
	for _, f := range files {
		rows = append(rows, fileRow{id: f.ID, count: len(f.Vectors)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	fmt.Fprintf(w, "Per-file vector counts:\n")
	for _, r := range rows {
		fmt.Fprintf(w, "  %-30s %d\n", r.id, r.count)
	}
	fmt.Fprintln(w)

	// Pending-by-workstream breakdown (only the gap-blockers).
	pending := report.PendingByWorkstream()
	if len(pending) > 0 {
		keys := make([]string, 0, len(pending))
		for k := range pending {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(w, "Pending dispatchers by workstream:\n")
		for _, k := range keys {
			fmt.Fprintf(w, "  Workstream %s: %d vectors\n", k, pending[k])
		}
		fmt.Fprintln(w)
	}

	// Fail/error detail (one line per).
	if report.Fail+report.Error > 0 {
		fmt.Fprintf(w, "Failures / errors:\n")
		for _, res := range report.Results {
			if res.Status == StatusFail || res.Status == StatusError {
				fmt.Fprintf(w, "  [%s] %s: %s\n", res.Status, res.VectorID, oneLine(res.Message))
			}
		}
	}
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:197] + "..."
	}
	return s
}
