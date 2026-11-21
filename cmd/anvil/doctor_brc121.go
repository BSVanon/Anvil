package main

import (
	"fmt"
	"time"
)

// doctorBRC121 prints one line on BRC-121 payments from the operator's view of
// /stats: whether the node offers them and, if not, why, and the journal of
// verified payments not yet recorded, with its oldest entry's age. A journal
// at its cap fails: verified payments are no longer kept. It returns the
// number of issues found.
func doctorBRC121(apiURL, token string) int {
	if token == "" {
		warn("BRC-121: no auth token configured, so /stats cannot show its state")
		return 0
	}
	stats := httpGetAuth(apiURL+"/stats", token)
	b, _ := stats["brc121"].(map[string]interface{})
	if b == nil {
		warn("BRC-121: /stats did not report it (a node older than this one)")
		return 0
	}
	if offered, _ := b["offered"].(bool); !offered {
		reason, _ := b["reason"].(string)
		pass("BRC-121: not offered (%s)", reason)
		return 0
	}
	j, _ := b["journal"].(map[string]interface{})
	entries, _ := j["entries"].(float64)
	limit, _ := j["cap"].(float64)
	age, _ := j["oldest_age_secs"].(float64)
	line := fmt.Sprintf("BRC-121: offered; journal %d of %d", int(entries), int(limit))
	if entries > 0 {
		line += fmt.Sprintf(", oldest %s", (time.Duration(age) * time.Second).String())
	}
	if limit > 0 && entries >= limit {
		fail("%s: full, verified payments are no longer kept", line)
		return 1
	}
	pass("%s", line)
	return 0
}
