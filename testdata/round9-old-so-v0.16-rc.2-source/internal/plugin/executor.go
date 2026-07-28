package plugin

import (
	"encoding/json"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard/internal/audit"
)

// blockExecution is intentionally fail-closed and contains no host callback or
// HTTP client path. Even a malformed request or a missing pending decision is
// refused before a streaming response can be created.
func (p *Plugin) blockExecution(raw []byte) []byte {
	var request pluginapi.ExecutorRequest
	_ = json.Unmarshal(raw, &request)
	body := request.OriginalRequest
	if len(body) == 0 {
		body = request.Payload
	}
	category := ""
	if len(body) != 0 {
		if decision, ok := p.pending.get(audit.HashRequest(body)); ok {
			category = decision.category
		}
	}
	p.counters.executorBlocks.Add(1)
	return errorEnvelope(blockedErrorCode, blockedResponseMessage(category), http.StatusForbidden, category)
}

func blockedResponseMessage(category string) string {
	type errorDetail struct {
		Message  string `json:"message"`
		Type     string `json:"type"`
		Code     string `json:"code"`
		Category string `json:"category,omitempty"`
	}
	payload, err := json.Marshal(struct {
		Error errorDetail `json:"error"`
	}{Error: errorDetail{
		Message:  refusalMessage,
		Type:     "policy_violation",
		Code:     blockedErrorCode,
		Category: category,
	}})
	if err != nil {
		return refusalMessage
	}
	return string(payload)
}
