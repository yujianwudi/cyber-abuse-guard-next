package csamtext

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestActionBlockProducerClosure keeps the independent CSAM action producer
// closed. A new block-capable return, another actionFor caller, or a call that
// escapes the reviewed complete/detected/eligible gate must fail until this
// contract is deliberately reviewed and updated.
func TestActionBlockProducerClosure(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("CSAM-text source inventory is empty")
	}

	var blockProducers []string
	var actionForCallers []string
	var source *ast.File
	var sourceSet *token.FileSet
	for _, path := range paths {
		if filepath.Ext(path) != ".go" || filepath.Base(path) == "producer_closure_test.go" {
			continue
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, data, parser.SkipObjectResolution)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		if filepath.Base(path) == "classifier.go" {
			source, sourceSet = file, fset
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			identity := closureFunctionIdentity(function)
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch value := node.(type) {
				case *ast.ReturnStmt:
					for _, expression := range value.Results {
						if identifier, ok := expression.(*ast.Ident); ok && identifier.Name == "ActionBlock" {
							blockProducers = append(blockProducers, filepath.ToSlash(path)+":"+identity)
						}
					}
				case *ast.CallExpr:
					if closureCallName(value.Fun) == "actionFor" {
						actionForCallers = append(actionForCallers, filepath.ToSlash(path)+":"+identity)
					}
				}
				return true
			})
		}
	}

	wantBlockProducer := []string{"classifier.go:actionFor"}
	wantActionCaller := []string{"classifier.go:(*Classifier).Classify"}
	assertClosedInventory(t, "ActionBlock producers", blockProducers, wantBlockProducer)
	assertClosedInventory(t, "actionFor callers", actionForCallers, wantActionCaller)
	if source == nil {
		t.Fatal("classifier.go was not scanned")
	}
	verifyClassifyBlockGate(t, sourceSet, source)
	verifyActionForEligibilityGate(t, sourceSet, source)
}

func TestActionBlockProducerClosureRejectsFixtures(t *testing.T) {
	base, err := os.ReadFile("classifier.go")
	if err != nil {
		t.Fatal(err)
	}
	fixtures := map[string][]byte{
		"unregistered-producer": append(append([]byte(nil), base...), []byte("\nfunc rogueAction() Action { return ActionBlock }\n")...),
		"eligible-bypass": []byte(strings.Replace(string(base),
			"best.Action = actionFor(mode, best.Eligible)",
			"best.Action = actionFor(mode, true)", 1)),
		"complete-gate-bypass": []byte(strings.Replace(string(base),
			"if best.Detected && best.Eligible && best.Coverage == CoverageComplete",
			"if best.Detected", 1)),
	}
	for name, source := range fixtures {
		t.Run(name, func(t *testing.T) {
			if err := classifierClosureError(source); err == nil {
				t.Fatalf("producer-closure validator accepted fixture %q", name)
			}
		})
	}
}

// classifierClosureError is intentionally independent of the source inventory
// test above. It is used with mutation fixtures so a new direct producer or a
// bypassed eligibility/completeness gate fails closed instead of merely
// changing the expected inventory.
func classifierClosureError(data []byte) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "classifier.go", data, parser.SkipObjectResolution)
	if err != nil {
		return err
	}
	var actionForCallers int
	var blockReturns int
	invalidProducer := false
	var classify, actionFor *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		if function.Name.Name == "Classify" && function.Recv != nil {
			classify = function
		}
		if function.Name.Name == "actionFor" && function.Recv == nil {
			actionFor = function
		}
		identity := closureFunctionIdentity(function)
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.ReturnStmt:
				for _, expression := range value.Results {
					if identifier, ok := expression.(*ast.Ident); ok && identifier.Name == "ActionBlock" {
						if identity != "actionFor" {
							invalidProducer = true
							return false
						}
						blockReturns++
					}
				}
			case *ast.CallExpr:
				if closureCallName(value.Fun) == "actionFor" {
					if identity != "(*Classifier).Classify" {
						invalidProducer = true
						return false
					}
					actionForCallers++
					if len(value.Args) != 2 {
						invalidProducer = true
						return false
					}
					arg, formatErr := closureNodeTextE(fset, value.Args[1])
					if formatErr != nil || arg != "best.Eligible" {
						invalidProducer = true
						return false
					}
				}
			}
			return true
		})
	}
	if invalidProducer || classify == nil || actionFor == nil || actionForCallers != 1 || blockReturns != 1 {
		return fmt.Errorf("producer inventory invalid=%v classify=%v actionFor=%v callers=%d blockReturns=%d", invalidProducer, classify != nil, actionFor != nil, actionForCallers, blockReturns)
	}
	if len(actionFor.Body.List) < 2 {
		return fmt.Errorf("actionFor eligibility guard missing")
	}
	guard, ok := actionFor.Body.List[0].(*ast.IfStmt)
	if !ok {
		return fmt.Errorf("actionFor eligibility guard missing")
	}
	guardText, err := closureNodeTextE(fset, guard.Cond)
	if err != nil || guardText != "!eligible" || astContainsIdentifier(guard.Body, "ActionBlock") {
		return fmt.Errorf("actionFor eligibility guard bypassed")
	}
	var gatedCalls int
	ast.Inspect(classify.Body, func(node ast.Node) bool {
		statement, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		ast.Inspect(statement.Body, func(inner ast.Node) bool {
			call, callOK := inner.(*ast.CallExpr)
			if callOK && closureCallName(call.Fun) == "actionFor" {
				gatedCalls++
				condition, formatErr := closureNodeTextE(fset, statement.Cond)
				if formatErr != nil || condition != "best.Detected && best.Eligible && best.Coverage == CoverageComplete" {
					gatedCalls = -100
				}
			}
			return true
		})
		return true
	})
	if gatedCalls != 1 {
		return fmt.Errorf("Classify complete gate bypassed: gatedCalls=%d", gatedCalls)
	}
	return nil
}

func verifyClassifyBlockGate(t *testing.T, fset *token.FileSet, file *ast.File) {
	t.Helper()
	function := closureFunction(t, file, "Classify", true)
	var calls int
	ast.Inspect(function.Body, func(node ast.Node) bool {
		statement, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		ast.Inspect(statement.Body, func(inner ast.Node) bool {
			call, callOK := inner.(*ast.CallExpr)
			if callOK && closureCallName(call.Fun) == "actionFor" {
				calls++
				condition := closureNodeText(t, fset, statement.Cond)
				if condition != "best.Detected && best.Eligible && best.Coverage == CoverageComplete" {
					t.Fatalf("actionFor escaped complete detected evidence gate: %s", condition)
				}
				if len(call.Args) != 2 || closureNodeText(t, fset, call.Args[1]) != "best.Eligible" {
					t.Fatalf("actionFor eligibility argument changed: %s", closureNodeText(t, fset, call))
				}
			}
			return true
		})
		return true
	})
	if calls != 1 {
		t.Fatalf("Classify actionFor calls=%d, want 1", calls)
	}
}

func verifyActionForEligibilityGate(t *testing.T, fset *token.FileSet, file *ast.File) {
	t.Helper()
	function := closureFunction(t, file, "actionFor", false)
	if len(function.Body.List) < 2 {
		t.Fatal("actionFor lost its fail-closed eligibility guard")
	}
	guard, ok := function.Body.List[0].(*ast.IfStmt)
	if !ok || closureNodeText(t, fset, guard.Cond) != "!eligible" {
		t.Fatalf("actionFor first statement is not !eligible guard: %s", closureNodeText(t, fset, function.Body.List[0]))
	}
	if astContainsIdentifier(guard.Body, "ActionBlock") {
		t.Fatal("ineligible actionFor branch can return ActionBlock")
	}
	blockReturns := 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		statement, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, expression := range statement.Results {
			if identifier, identOK := expression.(*ast.Ident); identOK && identifier.Name == "ActionBlock" {
				blockReturns++
			}
		}
		return true
	})
	if blockReturns != 1 {
		t.Fatalf("actionFor ActionBlock returns=%d, want 1", blockReturns)
	}
}

func closureFunction(t *testing.T, file *ast.File, name string, receiver bool) *ast.FuncDecl {
	t.Helper()
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == name && (function.Recv != nil) == receiver {
			return function
		}
	}
	t.Fatalf("function %s receiver=%t is missing", name, receiver)
	return nil
}

func closureFunctionIdentity(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return function.Name.Name
	}
	receiver := function.Recv.List[0].Type
	if star, ok := receiver.(*ast.StarExpr); ok {
		if identifier, identOK := star.X.(*ast.Ident); identOK {
			return "(*" + identifier.Name + ")." + function.Name.Name
		}
	}
	return "(receiver)." + function.Name.Name
}

func closureCallName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return value.Sel.Name
	case *ast.ParenExpr:
		return closureCallName(value.X)
	default:
		return ""
	}
}

func astContainsIdentifier(node ast.Node, name string) bool {
	found := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		identifier, ok := candidate.(*ast.Ident)
		if ok && identifier.Name == name {
			found = true
			return false
		}
		return !found
	})
	return found
}

func assertClosedInventory(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s=%v, want exactly %v", name, got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("%s=%v, want exactly %v", name, got, want)
		}
	}
}

func closureNodeText(t *testing.T, fset *token.FileSet, node ast.Node) string {
	t.Helper()
	text, err := closureNodeTextE(fset, node)
	if err != nil {
		t.Fatalf("format producer-closure AST: %v", err)
	}
	return text
}

func closureNodeTextE(fset *token.FileSet, node ast.Node) (string, error) {
	var buffer bytes.Buffer
	if err := format.Node(&buffer, fset, node); err != nil {
		return "", err
	}
	return buffer.String(), nil
}
