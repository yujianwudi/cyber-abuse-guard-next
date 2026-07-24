package classifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const maliciousTextProducerInventoryPath = "docs/reports/ROUND9_MALICIOUS_TEXT_PRODUCER_INVENTORY.json"

type maliciousTextProducerInventory struct {
	Schema            string                      `json:"schema"`
	ClaimBoundary     string                      `json:"claim_boundary"`
	ScanRoots         []string                    `json:"scan_roots"`
	BlockCapableCalls []string                    `json:"block_capable_calls"`
	Gates             []maliciousTextProducerGate `json:"gates"`
	Sites             []maliciousTextProducerSite `json:"sites"`
}

type maliciousTextProducerGate struct {
	ID                string `json:"id"`
	Path              string `json:"path"`
	Function          string `json:"function"`
	Contract          string `json:"contract"`
	FunctionASTSHA256 string `json:"function_ast_sha256"`
}

type maliciousTextProducerSite struct {
	ID            string `json:"id"`
	Path          string `json:"path"`
	Function      string `json:"function"`
	Kind          string `json:"kind"`
	Symbol        string `json:"symbol"`
	Ordinal       int    `json:"ordinal"`
	NodeASTSHA256 string `json:"node_ast_sha256"`
	GateID        string `json:"gate_id"`
	GateRelation  string `json:"gate_relation"`
}

type producerFunction struct {
	path     string
	identity string
	digest   string
	decl     *ast.FuncDecl
	fset     *token.FileSet
}

type discoveredProducerSite struct {
	path          string
	function      string
	kind          string
	symbol        string
	ordinal       int
	digest        string
	position      token.Pos
	node          ast.Node
	call          *ast.CallExpr
	functionEntry *producerFunction
}

type producerSourceScan struct {
	sites     []discoveredProducerSite
	functions map[string]*producerFunction
}

func TestRound9MaliciousTextProducerInventoryClosure(t *testing.T) {
	t.Parallel()
	root := classifierPolicyRepositoryRoot(t)
	inventory, err := loadMaliciousTextProducerInventory(root)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := loadMaliciousTextProducerSources(root, inventory.ScanRoots)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyMaliciousTextProducerInventory(inventory, sources); err != nil {
		t.Fatal(err)
	}

	t.Run("unregistered producer fails closed", func(t *testing.T) {
		fixture := cloneProducerSources(sources)
		fixture["internal/classifier/behavior.go"] = append(
			fixture["internal/classifier/behavior.go"],
			[]byte("\nfunc round9UnregisteredBlockProducer() Action { return ActionBlock }\n")...,
		)
		err := verifyMaliciousTextProducerInventory(inventory, fixture)
		if err == nil || !strings.Contains(err.Error(), "unregistered malicious-text producer site") {
			t.Fatalf("unregistered producer did not fail closed: %v", err)
		}
	})

	t.Run("package-level function literal producer fails closed", func(t *testing.T) {
		fixture := cloneProducerSources(sources)
		fixture["internal/classifier/behavior.go"] = append(
			fixture["internal/classifier/behavior.go"],
			[]byte("\nvar round9PackageLevelBlockProducer = func() Action { return ActionBlock }()\n")...,
		)
		err := verifyMaliciousTextProducerInventory(inventory, fixture)
		if err == nil || !strings.Contains(err.Error(), "unregistered malicious-text producer site") {
			t.Fatalf("package-level function literal producer did not fail closed: %v", err)
		}
	})

	t.Run("registered producer drift fails closed", func(t *testing.T) {
		fixture := cloneProducerSources(sources)
		path := "internal/classifier/classifier.go"
		original := fixture[path]
		mutated := bytes.Replace(original, []byte("return ActionBlock"), []byte("return Action(ActionBlock)"), 1)
		if bytes.Equal(mutated, original) {
			t.Fatal("registered producer drift fixture did not mutate source")
		}
		fixture[path] = mutated
		err := verifyMaliciousTextProducerInventory(inventory, fixture)
		if err == nil || !strings.Contains(err.Error(), "producer AST drift") {
			t.Fatalf("registered producer drift did not fail closed: %v", err)
		}
	})

	t.Run("candidate eligibility bypass fails closed", func(t *testing.T) {
		fixture := cloneProducerSources(sources)
		path := "internal/classifier/eligibility.go"
		original := fixture[path]
		mutated := bytes.Replace(
			original,
			[]byte("if eligibility.Eligible {\n\t\treturn actionFor(mode, score, thresholds)\n\t}"),
			[]byte("if eligibility.HarmfulCoreComplete {\n\t\treturn actionFor(mode, score, thresholds)\n\t}"),
			1,
		)
		if bytes.Equal(mutated, original) {
			t.Fatal("candidate eligibility bypass fixture did not mutate source")
		}
		fixture[path] = mutated
		err := verifyMaliciousTextProducerInventory(inventory, fixture)
		if err == nil || !strings.Contains(err.Error(), "candidate eligibility gate") {
			t.Fatalf("candidate eligibility bypass did not fail closed: %v", err)
		}
	})
}

func loadMaliciousTextProducerInventory(root string) (maliciousTextProducerInventory, error) {
	path := filepath.Join(root, filepath.FromSlash(maliciousTextProducerInventoryPath))
	file, err := os.Open(path)
	if err != nil {
		return maliciousTextProducerInventory{}, fmt.Errorf("open malicious-text producer inventory: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var inventory maliciousTextProducerInventory
	if err := decoder.Decode(&inventory); err != nil {
		return maliciousTextProducerInventory{}, fmt.Errorf("decode malicious-text producer inventory: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return maliciousTextProducerInventory{}, fmt.Errorf("malicious-text producer inventory has trailing JSON value")
		}
		return maliciousTextProducerInventory{}, fmt.Errorf("decode malicious-text producer inventory trailer: %w", err)
	}
	return inventory, nil
}

func loadMaliciousTextProducerSources(root string, scanRoots []string) (map[string][]byte, error) {
	if len(scanRoots) != 2 || scanRoots[0] != "cmd" || scanRoots[1] != "internal" {
		return nil, fmt.Errorf("malicious-text producer scan roots must be exactly cmd and internal")
	}
	sources := make(map[string][]byte)
	for _, relativeRoot := range scanRoots {
		absoluteRoot := filepath.Join(root, filepath.FromSlash(relativeRoot))
		err := filepath.WalkDir(absoluteRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("producer inventory refuses symlinked source: %s", path)
			}
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("producer inventory source is not regular: %s", path)
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sources[relative] = data
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk malicious-text producer sources below %s: %w", relativeRoot, err)
		}
	}
	return sources, nil
}

func cloneProducerSources(source map[string][]byte) map[string][]byte {
	clone := make(map[string][]byte, len(source))
	for path, data := range source {
		clone[path] = append([]byte(nil), data...)
	}
	return clone
}

func verifyMaliciousTextProducerInventory(
	inventory maliciousTextProducerInventory,
	sources map[string][]byte,
) error {
	if err := validateMaliciousTextProducerInventorySchema(inventory); err != nil {
		return err
	}
	scan, err := scanMaliciousTextProducerSources(sources, inventory.BlockCapableCalls)
	if err != nil {
		return err
	}
	if err := compareMaliciousTextProducerSites(inventory.Sites, scan.sites); err != nil {
		return err
	}
	if err := compareMaliciousTextProducerGates(inventory.Gates, scan.functions); err != nil {
		return err
	}
	if err := validateCandidateActionForGate(scan.functions); err != nil {
		return err
	}
	if err := validatePluginMaliciousTextGate(scan.functions); err != nil {
		return err
	}
	return nil
}

func validateMaliciousTextProducerInventorySchema(inventory maliciousTextProducerInventory) error {
	if inventory.Schema != "round9-malicious-text-producer-inventory/v1" {
		return fmt.Errorf("malicious-text producer inventory schema differs")
	}
	if inventory.ClaimBoundary != "static_source_closure_not_runtime_audit" {
		return fmt.Errorf("malicious-text producer inventory claim boundary differs")
	}
	if len(inventory.ScanRoots) != 2 || inventory.ScanRoots[0] != "cmd" || inventory.ScanRoots[1] != "internal" {
		return fmt.Errorf("malicious-text producer inventory scan roots differ")
	}
	if len(inventory.BlockCapableCalls) != 2 ||
		inventory.BlockCapableCalls[0] != "actionFor" ||
		inventory.BlockCapableCalls[1] != "candidateActionFor" {
		return fmt.Errorf("malicious-text producer block-capable call set differs")
	}
	return nil
}

func scanMaliciousTextProducerSources(
	sources map[string][]byte,
	blockCapableCalls []string,
) (producerSourceScan, error) {
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	callSet := make(map[string]struct{}, len(blockCapableCalls))
	for _, name := range blockCapableCalls {
		callSet[name] = struct{}{}
	}
	scan := producerSourceScan{functions: make(map[string]*producerFunction)}
	for _, path := range paths {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, sources[path], parser.SkipObjectResolution)
		if err != nil {
			return producerSourceScan{}, fmt.Errorf("parse producer source %s: %w", path, err)
		}
		packageEntry := &producerFunction{
			path:     path,
			identity: "<package-init>",
			fset:     fset,
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				inspectMaliciousTextProducerNodes(declaration, packageEntry, callSet, &scan.sites)
				continue
			}
			if function.Body == nil {
				continue
			}
			identity, err := producerFunctionIdentity(fset, function)
			if err != nil {
				return producerSourceScan{}, fmt.Errorf("identify function in %s: %w", path, err)
			}
			digest, err := producerFunctionDigest(fset, function)
			if err != nil {
				return producerSourceScan{}, fmt.Errorf("hash function %s in %s: %w", identity, path, err)
			}
			entry := &producerFunction{path: path, identity: identity, digest: digest, decl: function, fset: fset}
			key := producerFunctionKey(path, identity)
			if _, duplicate := scan.functions[key]; duplicate {
				return producerSourceScan{}, fmt.Errorf("duplicate producer function identity: %s", key)
			}
			scan.functions[key] = entry
			inspectMaliciousTextProducerNodes(function.Body, entry, callSet, &scan.sites)
		}
	}
	sort.Slice(scan.sites, func(i, j int) bool {
		left, right := scan.sites[i], scan.sites[j]
		if left.path != right.path {
			return left.path < right.path
		}
		if left.function != right.function {
			return left.function < right.function
		}
		if left.kind != right.kind {
			return left.kind < right.kind
		}
		if left.symbol != right.symbol {
			return left.symbol < right.symbol
		}
		return left.position < right.position
	})
	counts := make(map[string]int)
	for index := range scan.sites {
		key := strings.Join([]string{
			scan.sites[index].path,
			scan.sites[index].function,
			scan.sites[index].kind,
			scan.sites[index].symbol,
		}, "\x00")
		counts[key]++
		scan.sites[index].ordinal = counts[key]
	}
	return scan, nil
}

func inspectMaliciousTextProducerNodes(
	root ast.Node,
	entry *producerFunction,
	blockCapableCalls map[string]struct{},
	sites *[]discoveredProducerSite,
) {
	ast.Inspect(root, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.ReturnStmt:
			for _, expression := range value.Results {
				if symbol := directProducerSymbol(expression); symbol != "" {
					*sites = appendProducerSite(*sites, entry, "direct_return", symbol, value, nil)
				}
			}
		case *ast.AssignStmt:
			for _, expression := range value.Rhs {
				if symbol := directProducerSymbol(expression); symbol != "" {
					*sites = appendProducerSite(*sites, entry, "direct_assignment", symbol, value, nil)
				}
			}
		case *ast.ValueSpec:
			for _, expression := range value.Values {
				if symbol := directProducerSymbol(expression); symbol != "" {
					*sites = appendProducerSite(*sites, entry, "local_value", symbol, value, nil)
				}
			}
		case *ast.CompositeLit:
			for _, element := range value.Elts {
				field, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if symbol := directProducerSymbol(field.Value); symbol != "" {
					*sites = appendProducerSite(*sites, entry, "composite_field", symbol, field, nil)
				}
			}
		case *ast.CallExpr:
			name := producerCallName(value.Fun)
			if _, blockCapable := blockCapableCalls[name]; blockCapable {
				*sites = appendProducerSite(*sites, entry, "block_capable_call", name, value, value)
			}
		}
		return true
	})
}

func appendProducerSite(
	sites []discoveredProducerSite,
	function *producerFunction,
	kind string,
	symbol string,
	node ast.Node,
	call *ast.CallExpr,
) []discoveredProducerSite {
	digest, err := producerNodeDigest(function.fset, node)
	if err != nil {
		panic(err)
	}
	return append(sites, discoveredProducerSite{
		path:          function.path,
		function:      function.identity,
		kind:          kind,
		symbol:        symbol,
		digest:        digest,
		position:      node.Pos(),
		node:          node,
		call:          call,
		functionEntry: function,
	})
}

func directProducerSymbol(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return directProducerSymbol(value.X)
	case *ast.Ident:
		if value.Name == "ActionBlock" || value.Name == "decisionBlockMaliciousText" {
			return value.Name
		}
	case *ast.SelectorExpr:
		if value.Sel.Name == "ActionBlock" || value.Sel.Name == "decisionBlockMaliciousText" {
			return value.Sel.Name
		}
	case *ast.CallExpr:
		if len(value.Args) == 1 {
			if name := producerCallName(value.Fun); name == "Action" || name == "decisionKind" {
				return directProducerSymbol(value.Args[0])
			}
		}
	}
	return ""
}

func producerCallName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return value.Sel.Name
	case *ast.ParenExpr:
		return producerCallName(value.X)
	default:
		return ""
	}
}

func producerFunctionIdentity(fset *token.FileSet, function *ast.FuncDecl) (string, error) {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return function.Name.Name, nil
	}
	receiver, err := producerNodeText(fset, function.Recv.List[0].Type)
	if err != nil {
		return "", err
	}
	return "(" + receiver + ")." + function.Name.Name, nil
}

func producerFunctionDigest(fset *token.FileSet, function *ast.FuncDecl) (string, error) {
	clone := *function
	clone.Doc = nil
	return producerNodeDigest(fset, &clone)
}

func producerNodeDigest(fset *token.FileSet, node ast.Node) (string, error) {
	text, err := producerNodeText(fset, node)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(text))
	return hex.EncodeToString(digest[:]), nil
}

func producerNodeText(fset *token.FileSet, node any) (string, error) {
	var buffer bytes.Buffer
	if err := format.Node(&buffer, fset, node); err != nil {
		return "", err
	}
	return buffer.String(), nil
}

func producerFunctionKey(path, function string) string {
	return path + "::" + function
}

func producerSiteKey(path, function, kind, symbol string, ordinal int) string {
	return strings.Join([]string{path, function, kind, symbol, strconv.Itoa(ordinal)}, "::")
}

func compareMaliciousTextProducerSites(
	inventory []maliciousTextProducerSite,
	actual []discoveredProducerSite,
) error {
	byKey := make(map[string]maliciousTextProducerSite, len(inventory))
	ids := make(map[string]struct{}, len(inventory))
	previousID := ""
	for _, site := range inventory {
		if site.ID == "" || site.ID <= previousID {
			return fmt.Errorf("malicious-text producer site IDs must be non-empty and strictly sorted")
		}
		previousID = site.ID
		if _, duplicate := ids[site.ID]; duplicate {
			return fmt.Errorf("duplicate malicious-text producer site ID: %s", site.ID)
		}
		ids[site.ID] = struct{}{}
		key := producerSiteKey(site.Path, site.Function, site.Kind, site.Symbol, site.Ordinal)
		if _, duplicate := byKey[key]; duplicate {
			return fmt.Errorf("duplicate malicious-text producer site key: %s", key)
		}
		byKey[key] = site
	}
	seen := make(map[string]struct{}, len(actual))
	var unregistered []string
	for _, site := range actual {
		key := producerSiteKey(site.path, site.function, site.kind, site.symbol, site.ordinal)
		reviewed, ok := byKey[key]
		if !ok {
			unregistered = append(unregistered, fmt.Sprintf(
				"%s node_sha256=%s",
				key,
				site.digest,
			))
			continue
		}
		seen[key] = struct{}{}
		if reviewed.NodeASTSHA256 != site.digest {
			return fmt.Errorf("producer AST drift at %s: got %s want %s", key, site.digest, reviewed.NodeASTSHA256)
		}
		gateID, relation, err := expectedProducerGate(site)
		if err != nil {
			return err
		}
		if reviewed.GateID != gateID || reviewed.GateRelation != relation {
			return fmt.Errorf("producer eligibility relation drift at %s", key)
		}
	}
	if len(unregistered) != 0 {
		return fmt.Errorf("unregistered malicious-text producer site(s):\n%s", strings.Join(unregistered, "\n"))
	}
	var stale []string
	for key := range byKey {
		if _, ok := seen[key]; !ok {
			stale = append(stale, key)
		}
	}
	if len(stale) != 0 {
		sort.Strings(stale)
		return fmt.Errorf("registered malicious-text producer site(s) disappeared: %s", strings.Join(stale, ", "))
	}
	return nil
}

func expectedProducerGate(site discoveredProducerSite) (string, string, error) {
	switch {
	case site.kind == "direct_return" && site.symbol == "ActionBlock" &&
		site.path == "internal/classifier/classifier.go" && site.function == "actionFor":
		return "classifier-action-source", "raw_threshold_source_closed_by_registered_callers", nil
	case site.kind == "block_capable_call" && site.symbol == "candidateActionFor":
		return "classifier-candidate-eligibility", "candidate_action_for_requires_eligible", nil
	case site.kind == "block_capable_call" && site.symbol == "actionFor" && site.function == "candidateActionFor":
		return "classifier-candidate-eligibility", "eligible_branch_delegation", nil
	case site.kind == "block_capable_call" && site.symbol == "actionFor":
		if site.call == nil || len(site.call.Args) != 3 || !producerIntegerLiteral(site.call.Args[1], "0") {
			return "", "", fmt.Errorf("direct actionFor caller bypasses candidate eligibility gate: %s::%s", site.path, site.function)
		}
		return "plugin-eligible-malicious-winner", "neutral_zero_score_result_requires_plugin_winner", nil
	case site.kind == "direct_assignment" && site.symbol == "decisionBlockMaliciousText" &&
		site.path == "internal/plugin/disposition.go" && site.function == "inspectionDisposition":
		return "plugin-inspection-disposition", "eligible_winner_guarded_malicious_decision", nil
	case site.kind == "direct_assignment" && site.symbol == "ActionBlock" &&
		site.path == "internal/plugin/management.go":
		return "plugin-management-transport-projection", "transport_projection_preserves_separate_decision_kind", nil
	default:
		return "", "", fmt.Errorf(
			"unclassified malicious-text producer relation: %s",
			producerSiteKey(site.path, site.function, site.kind, site.symbol, site.ordinal),
		)
	}
}

func producerIntegerLiteral(expression ast.Expr, expected string) bool {
	literal, ok := expression.(*ast.BasicLit)
	return ok && literal.Kind == token.INT && literal.Value == expected
}

func compareMaliciousTextProducerGates(
	inventory []maliciousTextProducerGate,
	functions map[string]*producerFunction,
) error {
	expected := map[string]struct {
		path     string
		function string
		contract string
	}{
		"classifier-action-source": {
			path: "internal/classifier/classifier.go", function: "actionFor",
			contract: "raw ActionBlock source; every call edge is inventoried",
		},
		"classifier-candidate-eligibility": {
			path: "internal/classifier/eligibility.go", function: "candidateActionFor",
			contract: "actionFor is reachable with candidate score only under eligibility.Eligible",
		},
		"plugin-eligible-malicious-winner": {
			path: "internal/plugin/disposition.go", function: "eligibleMaliciousWinner",
			contract: "plugin requires CandidateBlockEligibility and closed winner proof",
		},
		"plugin-inspection-disposition": {
			path: "internal/plugin/disposition.go", function: "inspectionDisposition",
			contract: "ineligible ActionBlock is downgraded before block_malicious_text",
		},
		"plugin-management-transport-projection": {
			path: "internal/plugin/management.go", function: "(*Plugin).managementTest",
			contract: "management ActionBlock only projects the already typed inspection decision",
		},
	}
	if len(inventory) != len(expected) {
		ids := make([]string, 0, len(expected))
		for id := range expected {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		var discovered []string
		for _, id := range ids {
			contract := expected[id]
			function := functions[producerFunctionKey(contract.path, contract.function)]
			digest := "MISSING"
			if function != nil {
				digest = function.digest
			}
			discovered = append(discovered, fmt.Sprintf(
				"%s path=%s function=%s function_sha256=%s",
				id, contract.path, contract.function, digest,
			))
		}
		return fmt.Errorf(
			"malicious-text producer gate inventory is not closed: got %d want %d\n%s",
			len(inventory), len(expected), strings.Join(discovered, "\n"),
		)
	}
	seen := make(map[string]struct{}, len(inventory))
	previousID := ""
	for _, gate := range inventory {
		if gate.ID <= previousID {
			return fmt.Errorf("malicious-text producer gate IDs must be strictly sorted")
		}
		previousID = gate.ID
		contract, ok := expected[gate.ID]
		if !ok {
			return fmt.Errorf("unknown malicious-text producer gate: %s", gate.ID)
		}
		if gate.Path != contract.path || gate.Function != contract.function || gate.Contract != contract.contract {
			return fmt.Errorf("malicious-text producer gate metadata drift: %s", gate.ID)
		}
		function := functions[producerFunctionKey(gate.Path, gate.Function)]
		if function == nil {
			return fmt.Errorf("malicious-text producer gate function is missing: %s", gate.ID)
		}
		if gate.FunctionASTSHA256 != function.digest {
			label := "producer gate"
			if gate.ID == "classifier-candidate-eligibility" {
				label = "candidate eligibility gate"
			}
			return fmt.Errorf("%s AST drift at %s: got %s want %s", label, gate.ID, function.digest, gate.FunctionASTSHA256)
		}
		seen[gate.ID] = struct{}{}
	}
	for id := range expected {
		if _, ok := seen[id]; !ok {
			return fmt.Errorf("required malicious-text producer gate is unregistered: %s", id)
		}
	}
	return nil
}

func validateCandidateActionForGate(functions map[string]*producerFunction) error {
	function := functions[producerFunctionKey("internal/classifier/eligibility.go", "candidateActionFor")]
	if function == nil {
		return fmt.Errorf("candidate eligibility gate function is missing")
	}
	eligibleCalls := 0
	ast.Inspect(function.decl.Body, func(node ast.Node) bool {
		branch, ok := node.(*ast.IfStmt)
		if !ok || !producerSelector(branch.Cond, "eligibility", "Eligible") {
			return true
		}
		ast.Inspect(branch.Body, func(child ast.Node) bool {
			call, ok := child.(*ast.CallExpr)
			if ok && producerCallName(call.Fun) == "actionFor" {
				eligibleCalls++
			}
			return true
		})
		return true
	})
	if eligibleCalls != 1 {
		return fmt.Errorf("candidate eligibility gate must dominate exactly one actionFor delegation")
	}
	return nil
}

func producerSelector(expression ast.Expr, base, selector string) bool {
	selected, ok := expression.(*ast.SelectorExpr)
	if !ok || selected.Sel.Name != selector {
		return false
	}
	identifier, ok := selected.X.(*ast.Ident)
	return ok && identifier.Name == base
}

func validatePluginMaliciousTextGate(functions map[string]*producerFunction) error {
	winner := functions[producerFunctionKey("internal/plugin/disposition.go", "eligibleMaliciousWinner")]
	disposition := functions[producerFunctionKey("internal/plugin/disposition.go", "inspectionDisposition")]
	management := functions[producerFunctionKey("internal/plugin/management.go", "(*Plugin).managementTest")]
	if winner == nil || disposition == nil || management == nil {
		return fmt.Errorf("plugin malicious-text gate function is missing")
	}
	winnerText, err := producerNodeText(winner.fset, winner.decl)
	if err != nil {
		return err
	}
	for _, marker := range []string{"gate.Eligible", "CandidateIdentityBlockingProofComplete", "explanation.BlockEligible"} {
		if !strings.Contains(winnerText, marker) {
			return fmt.Errorf("plugin eligible malicious winner lost required proof marker: %s", marker)
		}
	}
	guarded := false
	ast.Inspect(disposition.decl.Body, func(node ast.Node) bool {
		statement, ok := node.(*ast.IfStmt)
		if !ok || !producerNegatedIdentifier(statement.Cond, "eligibleWinner") {
			return true
		}
		hasBreak := false
		ast.Inspect(statement.Body, func(child ast.Node) bool {
			branch, ok := child.(*ast.BranchStmt)
			if ok && branch.Tok == token.BREAK {
				hasBreak = true
			}
			return true
		})
		guarded = guarded || hasBreak
		return true
	})
	if !guarded {
		return fmt.Errorf("plugin inspection disposition lost ineligible winner downgrade")
	}
	managementGuarded := false
	ast.Inspect(management.decl.Body, func(node ast.Node) bool {
		clause, ok := node.(*ast.CaseClause)
		if !ok || len(clause.List) != 1 || !producerSelector(clause.List[0], "decision", "Block") {
			return true
		}
		for _, statement := range clause.Body {
			assignment, ok := statement.(*ast.AssignStmt)
			if !ok {
				continue
			}
			for _, expression := range assignment.Rhs {
				if directProducerSymbol(expression) == "ActionBlock" {
					managementGuarded = true
				}
			}
		}
		return true
	})
	if !managementGuarded {
		return fmt.Errorf("management ActionBlock is not a projection of decision.Block")
	}
	return nil
}

func producerNegatedIdentifier(expression ast.Expr, name string) bool {
	unary, ok := expression.(*ast.UnaryExpr)
	if !ok || unary.Op != token.NOT {
		return false
	}
	identifier, ok := unary.X.(*ast.Ident)
	return ok && identifier.Name == name
}
