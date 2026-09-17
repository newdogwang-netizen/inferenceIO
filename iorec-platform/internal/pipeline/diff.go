package pipeline

import "sort"

// InputDiff compares two normalized inputs (platform/07 §3).
type InputDiff struct {
	From                string              `json:"from"`
	To                  string              `json:"to"`
	Messages            map[string]int      `json:"messages"`
	Added               []int               `json:"added_indices"`
	Removed             []int               `json:"removed_indices"`
	Modified            []int               `json:"modified_indices"`
	SystemPromptChanged bool                `json:"system_prompt_changed"`
	Tools               map[string][]string `json:"tools"`
	ModelChanged        bool                `json:"model_changed"`
	TokenDelta          *float64            `json:"token_delta,omitempty"`
	ServerStateNote     string              `json:"server_state_note,omitempty"`
}

// ComputeInputDiff aligns message hash sequences by LCS.
func ComputeInputDiff(fromID, toID string, a, b *Normalized) InputDiff {
	d := InputDiff{From: fromID, To: toID, Messages: map[string]int{}, Tools: map[string][]string{"added": {}, "removed": {}}, Added: []int{}, Removed: []int{}, Modified: []int{}}
	if a == nil || b == nil {
		return d
	}
	ha, hb := a.MessageHashes, b.MessageHashes
	// LCS table
	n, m := len(ha), len(hb)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for k := m - 1; k >= 0; k-- {
			if ha[i] == hb[k] {
				lcs[i][k] = lcs[i+1][k+1] + 1
			} else if lcs[i+1][k] >= lcs[i][k+1] {
				lcs[i][k] = lcs[i+1][k]
			} else {
				lcs[i][k] = lcs[i][k+1]
			}
		}
	}
	i, k := 0, 0
	unchanged := 0
	for i < n && k < m {
		switch {
		case ha[i] == hb[k]:
			unchanged++
			i++
			k++
		case lcs[i+1][k] >= lcs[i][k+1]:
			d.Removed = append(d.Removed, i)
			i++
		default:
			d.Added = append(d.Added, k)
			k++
		}
	}
	for ; i < n; i++ {
		d.Removed = append(d.Removed, i)
	}
	for ; k < m; k++ {
		d.Added = append(d.Added, k)
	}
	// pair removed/added with same role at aligned positions as "modified"
	var rem2, add2 []int
	used := map[int]bool{}
	for _, ri := range d.Removed {
		matched := false
		for _, ai := range d.Added {
			if used[ai] {
				continue
			}
			if a.Messages[ri].Role == b.Messages[ai].Role && ri < len(b.Messages) && ai < len(a.Messages) && ai == ri {
				d.Modified = append(d.Modified, ai)
				used[ai] = true
				matched = true
				break
			}
		}
		if !matched {
			rem2 = append(rem2, ri)
		}
	}
	for _, ai := range d.Added {
		if !used[ai] {
			add2 = append(add2, ai)
		}
	}
	d.Removed, d.Added = orEmpty(rem2), orEmpty(add2)
	d.Messages["added"] = len(d.Added)
	d.Messages["removed"] = len(d.Removed)
	d.Messages["modified"] = len(d.Modified)
	d.Messages["unchanged"] = unchanged
	d.SystemPromptChanged = normalizeWS(a.System) != normalizeWS(b.System)
	d.ModelChanged = a.Model != b.Model
	ta, tb := map[string]bool{}, map[string]bool{}
	for _, t := range a.Tools {
		ta[t] = true
	}
	for _, t := range b.Tools {
		tb[t] = true
		if !ta[t] {
			d.Tools["added"] = append(d.Tools["added"], t)
		}
	}
	for _, t := range a.Tools {
		if !tb[t] {
			d.Tools["removed"] = append(d.Tools["removed"], t)
		}
	}
	sort.Strings(d.Tools["added"])
	sort.Strings(d.Tools["removed"])
	if pa, pb := promptTokens(a.Usage), promptTokens(b.Usage); pa != nil && pb != nil {
		delta := *pb - *pa
		d.TokenDelta = &delta
	}
	if len(b.ServerStateRefs) > 0 {
		d.ServerStateNote = "request references server-side state; only the client-sent increment is shown"
	}
	return d
}

func orEmpty(s []int) []int {
	if s == nil {
		return []int{}
	}
	return s
}

func promptTokens(u map[string]any) *float64 {
	for _, k := range []string{"prompt_tokens", "input_tokens", "promptTokenCount"} {
		if v, ok := u[k].(float64); ok {
			return &v
		}
	}
	return nil
}
