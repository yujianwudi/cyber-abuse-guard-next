package round9corpus

import (
	"fmt"
	"math"
	"net/http"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

const maliciousRouteSchema = "round9-malicious-route-executions/v1"

// MaliciousFailure is deliberately text-free. It identifies every failed
// externally labelled route without persisting the request payload.
type MaliciousFailure struct {
	BaseID           string            `json:"base_id"`
	RouteID          string            `json:"route_id"`
	ExpectedCategory rules.Category    `json:"expected_category"`
	ObservedCategory rules.Category    `json:"observed_category,omitempty"`
	ObservedAction   classifier.Action `json:"observed_action"`
	BlockEligible    bool              `json:"block_eligible"`
}

// MaliciousCategoryMetrics reports semantic recall separately from route
// execution coverage. A semantic sample passes only when every required
// Chat/Responses, stream/nonstream, Balanced/Strict active route passes.
type MaliciousCategoryMetrics struct {
	SemanticSamples       int     `json:"semantic_samples"`
	SemanticBlocked       int     `json:"semantic_blocked"`
	RouteExecutions       int     `json:"route_executions"`
	PassedRouteExecutions int     `json:"passed_route_executions"`
	RecallPercent         float64 `json:"recall_percent"`
	Wilson95LowerPercent  float64 `json:"wilson_95_lower_percent"`
	Wilson95UpperPercent  float64 `json:"wilson_95_upper_percent"`
}

// MaliciousMetrics keeps externally labelled semantic samples distinct from
// serialized route executions and discloses every failed sample/route ID.
type MaliciousMetrics struct {
	Schema                    string                              `json:"schema"`
	UniqueSemanticSamples     int                                 `json:"unique_semantic_samples"`
	SemanticBlocked           int                                 `json:"semantic_blocked"`
	SerializedRouteExecutions int                                 `json:"serialized_route_executions"`
	PassedRouteExecutions     int                                 `json:"passed_route_executions"`
	CategoryCounts            map[string]int                      `json:"category_counts"`
	LanguageCounts            map[string]int                      `json:"language_counts"`
	ProtocolCounts            map[string]int                      `json:"protocol_counts"`
	StreamCounts              map[string]int                      `json:"stream_counts"`
	ModeCounts                map[string]int                      `json:"mode_counts"`
	PerCategory               map[string]MaliciousCategoryMetrics `json:"per_category"`
	Failures                  []MaliciousFailure                  `json:"failures"`
}

// BuildMaliciousRoutes emits eight active executions per semantic base: both
// OpenAI protocols, stream/nonstream, and Balanced/Strict. These wrappers are
// route executions and never increase the semantic-sample denominator.
func BuildMaliciousRoutes(records []MaliciousRecord) ([]RouteExecution, error) {
	routes := make([]RouteExecution, 0, len(records)*8)
	for _, record := range records {
		for _, variant := range []struct {
			protocol string
			stream   bool
		}{
			{protocol: "openai_chat", stream: false},
			{protocol: "openai_chat", stream: true},
			{protocol: "openai_responses", stream: false},
			{protocol: "openai_responses", stream: true},
		} {
			body, err := serializeDirect(record.Prompt, variant.protocol, variant.stream)
			if err != nil {
				return nil, err
			}
			for _, mode := range []classifier.Mode{classifier.ModeBalanced, classifier.ModeStrict} {
				routes = append(routes, RouteExecution{
					ID:     fmt.Sprintf("%s-%s-%t-%s", record.ID, variant.protocol, variant.stream, mode),
					BaseID: record.ID, Protocol: variant.protocol, Carrier: "current_user_direct",
					Mode: mode, Stream: variant.stream, Body: body,
				})
			}
		}
	}
	return routes, nil
}

// EvaluateMaliciousRoutes evaluates externally frozen ground truth. Candidate
// eligibility is observed only as an output: it never defines the denominator
// or rewrites a label.
func EvaluateMaliciousRoutes(records []MaliciousRecord, routes []RouteExecution) (MaliciousMetrics, error) {
	set, err := rules.LoadDefault()
	if err != nil {
		return MaliciousMetrics{}, fmt.Errorf("load rules: %w", err)
	}
	engine, err := classifier.New(set)
	if err != nil {
		return MaliciousMetrics{}, fmt.Errorf("compile classifier: %w", err)
	}
	byID := make(map[string]MaliciousRecord, len(records))
	expectedCategories := make(map[string]rules.Category, len(records))
	metrics := MaliciousMetrics{
		Schema: maliciousRouteSchema, UniqueSemanticSamples: len(records),
		CategoryCounts: map[string]int{}, LanguageCounts: map[string]int{},
		ProtocolCounts: map[string]int{}, StreamCounts: map[string]int{}, ModeCounts: map[string]int{},
		PerCategory: map[string]MaliciousCategoryMetrics{},
		Failures:    make([]MaliciousFailure, 0),
	}
	for _, record := range records {
		if _, duplicate := byID[record.ID]; duplicate {
			return MaliciousMetrics{}, fmt.Errorf("duplicate malicious base id %q", record.ID)
		}
		expected, err := ExpectedRuleCategory(record.Category)
		if err != nil {
			return MaliciousMetrics{}, err
		}
		byID[record.ID] = record
		expectedCategories[record.ID] = expected
		metrics.CategoryCounts[record.Category]++
		metrics.LanguageCounts[record.Language]++
		category := metrics.PerCategory[record.Category]
		category.SemanticSamples++
		metrics.PerCategory[record.Category] = category
	}

	seenRoutes := make(map[string]struct{}, len(routes))
	passedPerBase := make(map[string]int, len(records))
	for _, route := range routes {
		record, ok := byID[route.BaseID]
		if !ok {
			return MaliciousMetrics{}, fmt.Errorf("malicious route %q references unknown base %q", route.ID, route.BaseID)
		}
		if _, duplicate := seenRoutes[route.ID]; duplicate {
			return MaliciousMetrics{}, fmt.Errorf("duplicate malicious route id %q", route.ID)
		}
		seenRoutes[route.ID] = struct{}{}
		profile, err := routeProfile(route.Protocol)
		if err != nil {
			return MaliciousMetrics{}, fmt.Errorf("malicious route %q: %w", route.ID, err)
		}
		extracted, err := extract.ExtractProfiledRequest(
			route.Body,
			http.Header{"Content-Type": []string{"application/json"}},
			extract.RequestProfile{Source: profile},
			extract.Limits{},
		)
		if err != nil || !extracted.IsComplete() {
			return MaliciousMetrics{}, fmt.Errorf("malicious route %q extraction incomplete: err=%v parse=%q", route.ID, err, extracted.ParseError)
		}
		result := classifyExtracted(engine, extracted, route.Mode)
		eligible := result.BlockEligibility != nil && result.BlockEligibility.Eligible
		expected := expectedCategories[route.BaseID]
		passed := result.Action == classifier.ActionBlock && eligible && result.Category == expected

		metrics.SerializedRouteExecutions++
		metrics.ProtocolCounts[route.Protocol]++
		metrics.StreamCounts[fmt.Sprintf("%t", route.Stream)]++
		metrics.ModeCounts[string(route.Mode)]++
		category := metrics.PerCategory[record.Category]
		category.RouteExecutions++
		if passed {
			metrics.PassedRouteExecutions++
			category.PassedRouteExecutions++
			passedPerBase[route.BaseID]++
		} else {
			metrics.Failures = append(metrics.Failures, MaliciousFailure{
				BaseID: route.BaseID, RouteID: route.ID, ExpectedCategory: expected,
				ObservedCategory: result.Category, ObservedAction: result.Action, BlockEligible: eligible,
			})
		}
		metrics.PerCategory[record.Category] = category
	}
	if metrics.SerializedRouteExecutions != len(records)*8 {
		return MaliciousMetrics{}, fmt.Errorf("malicious serialized routes=%d want %d", metrics.SerializedRouteExecutions, len(records)*8)
	}
	for _, record := range records {
		if passedPerBase[record.ID] != 8 {
			continue
		}
		metrics.SemanticBlocked++
		category := metrics.PerCategory[record.Category]
		category.SemanticBlocked++
		metrics.PerCategory[record.Category] = category
	}
	for categoryName, category := range metrics.PerCategory {
		lower, upper := WilsonInterval95(category.SemanticBlocked, category.SemanticSamples)
		category.RecallPercent = percentage(category.SemanticBlocked, category.SemanticSamples)
		category.Wilson95LowerPercent = lower * 100
		category.Wilson95UpperPercent = upper * 100
		metrics.PerCategory[categoryName] = category
	}
	return metrics, nil
}

func percentage(events, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(events) * 100 / float64(total)
}

// WilsonInterval95 returns the two-sided 95% Wilson score interval.
func WilsonInterval95(events, total int) (float64, float64) {
	if total <= 0 || events < 0 || events > total {
		return 0, 1
	}
	const z = 1.959963984540054
	n := float64(total)
	p := float64(events) / n
	z2 := z * z
	center := p + z2/(2*n)
	margin := z * math.Sqrt(p*(1-p)/n+z2/(4*n*n))
	denominator := 1 + z2/n
	lower := (center - margin) / denominator
	upper := (center + margin) / denominator
	if lower < 0 {
		lower = 0
	}
	if upper > 1 {
		upper = 1
	}
	return lower, upper
}
