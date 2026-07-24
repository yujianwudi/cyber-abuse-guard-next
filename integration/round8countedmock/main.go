// round8-counted-mock is a private, body-discarding OpenAI-compatible upstream
// used only by the Round 8 Linux Host evidence runner.
package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	contractName   = "round8-counted-mock/v1"
	listenAddress  = ":18080"
	maxRequestBody = 32 << 20
)

type countedMock struct {
	total atomic.Uint64
}

type requestEnvelope struct {
	Stream bool `json:"stream"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeEnvelope(w http.ResponseWriter, r *http.Request) (requestEnvelope, error) {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	var envelope requestEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return requestEnvelope{}, err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return requestEnvelope{}, errors.New("multiple JSON values")
		}
		return requestEnvelope{}, err
	}
	return envelope, nil
}

func (m *countedMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/healthz":
		writeJSON(w, http.StatusOK, map[string]any{
			"contract":               contractName,
			"healthy":                true,
			"request_body_retention": false,
		})
	case r.Method == http.MethodPost && r.URL.Path == "/__cag/reset":
		m.total.Store(0)
		writeJSON(w, http.StatusOK, map[string]any{"total": 0})
	case r.Method == http.MethodGet && r.URL.Path == "/__cag/stats":
		writeJSON(w, http.StatusOK, map[string]any{"total": m.total.Load()})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
		m.serveChat(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/responses":
		m.serveResponses(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (m *countedMock) serveChat(w http.ResponseWriter, r *http.Request) {
	envelope, err := decodeEnvelope(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	m.total.Add(1)
	if envelope.Stream {
		writeSSE(w, []string{
			`{"id":"chatcmpl-round8","object":"chat.completion.chunk","created":0,"model":"round8-test-model","choices":[{"index":0,"delta":{"role":"assistant","content":"ok"},"finish_reason":null}]}`,
			`{"id":"chatcmpl-round8","object":"chat.completion.chunk","created":0,"model":"round8-test-model","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
			`[DONE]`,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      "chatcmpl-round8",
		"object":  "chat.completion",
		"created": 0,
		"model":   "round8-test-model",
		"choices": []any{map[string]any{
			"index": 0,
			"message": map[string]any{
				"role":    "assistant",
				"content": "ok",
			},
			"finish_reason": "stop",
		}},
		"usage": map[string]int{
			"prompt_tokens":     1,
			"completion_tokens": 1,
			"total_tokens":      2,
		},
	})
}

func (m *countedMock) serveResponses(w http.ResponseWriter, r *http.Request) {
	envelope, err := decodeEnvelope(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	m.total.Add(1)
	response := `{"id":"resp_round8","object":"response","created_at":0,"status":"completed","model":"round8-test-model","output":[{"id":"msg_round8","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"ok","annotations":[]}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`
	if envelope.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "event: response.created\ndata: "+response+"\n\n")
		_, _ = io.WriteString(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_round8\",\"output_index\":0,\"content_index\":0,\"delta\":\"ok\"}\n\n")
		_, _ = io.WriteString(w, "event: response.completed\ndata: "+response+"\n\n")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, response)
}

func writeSSE(w http.ResponseWriter, frames []string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	for _, frame := range frames {
		_, _ = io.WriteString(w, "data: "+frame+"\n\n")
	}
}

func main() {
	server := &http.Server{
		Addr:              listenAddress,
		Handler:           &countedMock{},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		panic("counted Mock listener failed")
	}
}
