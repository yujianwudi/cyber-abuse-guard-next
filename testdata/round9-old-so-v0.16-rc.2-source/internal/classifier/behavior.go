package classifier

import (
	"sort"
	"strings"

	"github.com/yujianwudi/cyber-abuse-guard/internal/rules"
)

// BehaviorRelation is a privacy-safe edge in the deterministic behavior
// model. Nodes and predicates are stable identifiers; prompt spans are never
// retained or returned.
type BehaviorRelation struct {
	From      string `json:"from"`
	Predicate string `json:"predicate"`
	To        string `json:"to"`
}

// BehaviorGraph is the explainable relation model behind a classification.
// It describes which semantic dimensions were present and how they combined,
// without carrying raw request text or matched fragments.
type BehaviorGraph struct {
	Actor              string             `json:"actor,omitempty"`
	BaseBehavior       bool               `json:"base_behavior"`
	Intent             bool               `json:"intent"`
	Action             bool               `json:"action"`
	Object             bool               `json:"object"`
	Target             bool               `json:"target"`
	Destination        bool               `json:"destination"`
	Technique          bool               `json:"technique"`
	Operationalization bool               `json:"operationalization"`
	DeliveryExecution  bool               `json:"delivery_execution"`
	CredentialAccess   bool               `json:"credential_access"`
	Persistence        bool               `json:"persistence"`
	Evasion            bool               `json:"evasion"`
	Exfiltration       bool               `json:"exfiltration"`
	Impact             bool               `json:"impact"`
	Scale              bool               `json:"scale"`
	Authorization      bool               `json:"authorization"`
	Defensive          bool               `json:"defensive"`
	Remediation        bool               `json:"remediation"`
	StaticAnalysis     bool               `json:"static_analysis"`
	IncidentResponse   bool               `json:"incident_response"`
	HighLevel          bool               `json:"high_level"`
	CTFOrLab           bool               `json:"ctf_or_lab"`
	Wrapper            bool               `json:"wrapper"`
	Amplifier          bool               `json:"amplifier"`
	RoleScope          string             `json:"role_scope,omitempty"`
	Carrier            string             `json:"carrier,omitempty"`
	Composition        string             `json:"composition,omitempty"`
	Relations          []BehaviorRelation `json:"relations,omitempty"`
	ReasonCodes        []string           `json:"reason_codes,omitempty"`
}

func metaControlAuditScore(score int, thresholds Thresholds) int {
	if score < thresholds.Audit {
		return score
	}
	// Wrapper-only evidence is an audit signal, not cyber-abuse risk. Keep the
	// reported score at the configured audit boundary so it cannot independently
	// cross balanced or hard-block thresholds.
	return thresholds.Audit
}

func actionForMetaControl(mode Mode, score int, thresholds Thresholds) Action {
	if score < thresholds.Audit {
		return ActionAllow
	}
	switch mode {
	case ModeOff:
		return ActionAllow
	case ModeObserve:
		return ActionObserve
	default:
		// Even strict mode reports wrapper-only control evidence as audit. A block
		// still requires an independently established cyber-abuse behavior.
		return ActionAudit
	}
}

func attachBehaviorGraph(result *Result, roleScope, carrier string) {
	if result == nil {
		return
	}
	if carrier == "" && result.Behavior != nil {
		carrier = result.Behavior.Carrier
	}
	graph := behaviorGraphFor(*result, roleScope, carrier)
	if graph == nil {
		result.Behavior = nil
		return
	}
	result.Behavior = graph
}

func behaviorGraphFor(result Result, roleScope, carrier string) *BehaviorGraph {
	if result.Category == "" && len(result.Evidence) == 0 && result.Context == (ContextFlags{}) {
		return nil
	}
	graph := &BehaviorGraph{
		BaseBehavior:     result.Category != "",
		Authorization:    result.Context.Authorized,
		Defensive:        result.Context.Defensive,
		Remediation:      result.Context.Remediation,
		StaticAnalysis:   result.Context.StaticAnalysis,
		IncidentResponse: result.Context.IncidentResponse,
		HighLevel:        result.Context.HighLevel,
		CTFOrLab:         result.Context.CTFOrLab,
		RoleScope:        roleScope,
		Carrier:          carrier,
	}
	if graph.BaseBehavior {
		graph.Actor = "requester"
		graph.Intent = true
		graph.Action = true
		graph.Object = true
	}
	for _, evidence := range result.Evidence {
		switch evidence.Kind {
		case "intent", "harm":
			graph.Intent = true
		case "action":
			graph.Action = true
			graph.Operationalization = true
		case "object":
			graph.Object = true
		case "operational", "sequence":
			graph.Action = true
			graph.Operationalization = true
			graph.DeliveryExecution = true
		case "target":
			graph.Target = true
		case "destination":
			graph.Destination = true
		case "evasion":
			graph.Evasion = true
			graph.Technique = true
		case "scale":
			graph.Scale = true
		case "impact", "outcome":
			graph.Impact = true
		case "meta_override":
			graph.Wrapper = true
		}
	}
	if graph.Wrapper && graph.Actor == "" {
		graph.Actor = "requester"
	}
	graph.Amplifier = graph.Wrapper && graph.BaseBehavior
	graph.Technique = graph.Technique || graph.Operationalization

	switch result.Category {
	case rules.CategoryCredentialTheft:
		graph.CredentialAccess = true
	case rules.CategoryPhishing:
		graph.DeliveryExecution = true
		graph.CredentialAccess = true
	case rules.CategoryMalware:
		graph.DeliveryExecution = true
		graph.Persistence = graph.Operationalization || graph.Impact
	case rules.CategoryRansomware:
		graph.DeliveryExecution = true
		graph.Impact = true
	case rules.CategoryExploitation:
		graph.CredentialAccess = true
	case rules.CategoryDisruption:
		graph.Impact = true
	case rules.CategoryExfiltration:
		graph.Exfiltration = true
	case rules.CategoryEvasion:
		graph.Evasion = true
		graph.Technique = true
	}

	graph.Composition = behaviorComposition(result, graph)
	graph.Relations = behaviorRelations(graph)
	graph.ReasonCodes = behaviorReasonCodes(graph)
	return graph
}

func behaviorComposition(result Result, graph *BehaviorGraph) string {
	if !graph.BaseBehavior {
		if graph.Wrapper {
			return "control_signal_only"
		}
		return "context_only"
	}
	for _, ruleID := range result.RuleIDs {
		if strings.HasPrefix(ruleID, "SEMANTIC-") {
			return "bounded_semantic_window"
		}
	}
	ordinary := 0
	for _, ruleID := range result.RuleIDs {
		if ruleID != metaOverrideRuleID {
			ordinary++
		}
	}
	if ordinary > 1 {
		return "same_category_composition"
	}
	return "rule_local"
}

func behaviorRelations(graph *BehaviorGraph) []BehaviorRelation {
	relations := make([]BehaviorRelation, 0, 12)
	add := func(condition bool, from, predicate, to string) {
		if condition {
			relations = append(relations, BehaviorRelation{From: from, Predicate: predicate, To: to})
		}
	}
	add(graph.BaseBehavior, "requester", "requests", "action")
	add(graph.Object, "action", "affects", "object")
	add(graph.Target, "action", "targets", "target")
	add(graph.Technique, "action", "uses", "technique")
	add(graph.DeliveryExecution, "action", "delivered_or_executed_by", "execution")
	add(graph.CredentialAccess, "action", "seeks", "credential_or_access")
	add(graph.Persistence, "action", "establishes", "persistence")
	add(graph.Evasion, "action", "evades", "defense")
	add(graph.Exfiltration, "object", "moves_via", "exfiltration")
	add(graph.Impact, "action", "causes", "impact")
	add(graph.Scale, "action", "applies_at", "scale")
	add(graph.Amplifier, "wrapper", "amplifies", "base_behavior")
	add(graph.Wrapper && !graph.BaseBehavior, "wrapper", "observed_without", "base_behavior")
	add(graph.Authorization && graph.BaseBehavior, "authorization", "constrains", "base_behavior")
	add((graph.Defensive || graph.Remediation || graph.StaticAnalysis || graph.IncidentResponse || graph.HighLevel) && graph.BaseBehavior,
		"safety_context", "constrains", "base_behavior")
	return relations
}

func behaviorReasonCodes(graph *BehaviorGraph) []string {
	reasons := make([]string, 0, 16)
	add := func(condition bool, value string) {
		if condition {
			reasons = append(reasons, value)
		}
	}
	add(graph.BaseBehavior, "base_behavior_present")
	add(graph.Operationalization, "operationalization_present")
	add(graph.DeliveryExecution, "delivery_execution_present")
	add(graph.CredentialAccess, "credential_access_present")
	add(graph.Persistence, "persistence_present")
	add(graph.Technique, "technique_present")
	add(graph.Target, "target_present")
	add(graph.Destination, "destination_present")
	add(graph.Evasion, "evasion_present")
	add(graph.Exfiltration, "exfiltration_relation_present")
	add(graph.Impact, "impact_present")
	add(graph.Scale, "scale_present")
	add(graph.Authorization, "authorization_context_present")
	add(graph.Defensive, "defensive_context_present")
	add(graph.Remediation, "remediation_context_present")
	add(graph.StaticAnalysis, "static_analysis_context_present")
	add(graph.IncidentResponse, "incident_response_context_present")
	add(graph.HighLevel, "high_level_context_present")
	add(graph.CTFOrLab, "bounded_lab_context_present")
	add(graph.Amplifier, "wrapper_amplifies_base_behavior")
	add(graph.Wrapper && !graph.BaseBehavior, "wrapper_without_base_behavior")
	sort.Strings(reasons)
	return reasons
}
