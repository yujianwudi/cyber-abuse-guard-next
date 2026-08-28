package cpalatestcontract

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const latestCPATokenSeparator = "\x1f"

type latestCPASourceSyntax struct {
	path string
	data []byte
	fset *token.FileSet
	file *ast.File
}

func TestLatestCPARequestLoggingStartupSourceContract(t *testing.T) {
	module := resolveLatestCPASourceOffline(t)
	source := parseLatestCPASource(t, module.Dir, "internal", "api", "server.go")
	newServer := source.mustFunction(t, "NewServer")
	newServerTokens := source.nodeTokens(newServer)
	commercialGuard := source.mustIfCondition(t, newServer, `!cfg.CommercialMode`)
	commercialGuardTokens := source.nodeTokens(commercialGuard.Body)

	requireLatestCPASequenceOnlyWithin(t, newServerTokens, commercialGuardTokens,
		`optionState.requestLoggerFactory(`, "request logger factory")
	requireLatestCPASequence(t, commercialGuardTokens,
		`requestLogger = optionState.requestLoggerFactory(cfg, configFilePath)`,
		"request logger creation under !cfg.CommercialMode")
	requireLatestCPASequenceOnlyWithin(t, newServerTokens, commercialGuardTokens,
		`middleware.RequestLoggingMiddleware(`, "RequestLoggingMiddleware construction")
	requireLatestCPASequence(t, commercialGuardTokens,
		`engine.Use(middleware.RequestLoggingMiddleware(requestLogger))`,
		"RequestLoggingMiddleware installation under !cfg.CommercialMode")
}

func TestLatestCPARequestLoggingReloadSourceContract(t *testing.T) {
	module := resolveLatestCPASourceOffline(t)
	source := parseLatestCPASource(t, module.Dir, "internal", "api", "server_reload.go")
	reloadTokens := source.allTokens()
	updateTokens := source.nodeTokens(source.mustFunction(t, "UpdateClientsContext"))

	requireLatestCPASequenceAbsent(t, reloadTokens, `CommercialMode`,
		"server_reload.go commercial-mode branch")
	requireLatestCPASequenceAbsent(t, reloadTokens, `RequestLoggingMiddleware`,
		"server_reload.go middleware construction")
	requireLatestCPASequence(t, updateTokens,
		`s.requestLogger != nil && (oldCfg == nil || previousRequestLog != cfg.RequestLog)`,
		"RequestLog-only reload guard")
	requireLatestCPASequenceCount(t, updateTokens, `s.loggerToggle(cfg.RequestLog)`, 1,
		"loggerToggle RequestLog update")
	requireLatestCPASequenceCount(t, updateTokens, `toggler.SetEnabled(cfg.RequestLog)`, 1,
		"SetEnabled RequestLog update")
	for _, forbidden := range []string{
		`s.requestLogger =`,
		`s.loggerToggle =`,
		`s.engine`,
	} {
		requireLatestCPASequenceAbsent(t, updateTokens, forbidden,
			"UpdateClientsContext installed middleware mutation")
	}
}

func TestLatestCPARequestLoggingErrorOnlyCaptureSourceContract(t *testing.T) {
	module := resolveLatestCPASourceOffline(t)
	source := parseLatestCPASource(t, module.Dir, "internal", "api", "middleware", "request_logging.go")
	middlewareTokens := source.nodeTokens(source.mustFunction(t, "RequestLoggingMiddleware"))

	skipMethod := `if shouldSkipMethodForRequestLogging(c.Request) { c.Next(); return }`
	pathGuard := `if !shouldLogRequest(path) { c.Next(); return }`
	loggerProbe := `loggerEnabled := logger.IsEnabled()`
	requireLatestCPASequenceCount(t, middlewareTokens, skipMethod, 1,
		"request-method skip guard")
	requireLatestCPASequenceBefore(t, middlewareTokens, skipMethod, pathGuard,
		"request-method guard before path guard")
	requireLatestCPASequenceCount(t, middlewareTokens, pathGuard, 1,
		"non-management/loggable path guard")
	requireLatestCPASequenceBefore(t, middlewareTokens, pathGuard, loggerProbe,
		"path guard before logger capture")
	requireLatestCPASequence(t, middlewareTokens,
		`captureBody := shouldCaptureRequestBody(loggerEnabled, c.Request)`,
		"disabled-aware request body capture choice")
	requireLatestCPASequence(t, middlewareTokens,
		`requestInfo, err := captureRequestInfo(c, captureBody)`,
		"request capture construction")
	requireLatestCPASequence(t, middlewareTokens,
		`wrapper := NewResponseWriterWrapper(c.Writer, logger, requestInfo)`,
		"response capture construction")
	requireLatestCPASequence(t, middlewareTokens,
		`if !loggerEnabled { wrapper.logOnErrorOnly = true }`,
		"disabled logger error-only response capture")
	requireLatestCPASequence(t, middlewareTokens,
		`attachDeferredRequestBodyCapture(c.Request, logger, requestInfo, loggerEnabled, captureBody)`,
		"disabled logger deferred body capture")

	shouldCaptureTokens := source.nodeTokens(source.mustFunction(t, "shouldCaptureRequestBody"))
	requireLatestCPASequence(t, shouldCaptureTokens, `if loggerEnabled { return true }`,
		"enabled logger full-body capture")
	requireLatestCPASequence(t, shouldCaptureTokens,
		`return req.ContentLength <= maxErrorOnlyCapturedRequestBodyBytes`,
		"bounded full-body capture while the logger is disabled")

	captureInfoTokens := source.nodeTokens(source.mustFunction(t, "captureRequestInfo"))
	bodyReadGuard := `if captureBody && c.Request.Body != nil {`
	bodyRead := `bodyBytes, err := io.ReadAll(c.Request.Body)`
	requireLatestCPASequence(t, captureInfoTokens, bodyReadGuard,
		"captureBody request-body read guard")
	requireLatestCPASequenceBefore(t, captureInfoTokens, bodyReadGuard, bodyRead,
		"guarded complete request-body read")
	requireLatestCPASequence(t, captureInfoTokens,
		`c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))`,
		"request body restoration after capture")

	shouldLogTokens := source.nodeTokens(source.mustFunction(t, "shouldLogRequest"))
	requireLatestCPASequence(t, shouldLogTokens,
		`if strings.HasPrefix(path, "/v0/management") || strings.HasPrefix(path, "/management") { return false }`,
		"explicit management path exclusion")
	requireLatestCPASequence(t, shouldLogTokens, `return true`,
		"non-management path admission")

	methodTokens := source.nodeTokens(source.mustFunction(t, "shouldSkipMethodForRequestLogging"))
	requireLatestCPASequence(t, methodTokens,
		`if req.Method != http.MethodGet { return false }`,
		"exact uppercase GET-only request-log skip")
}

func TestLatestCPAStartupPrivacyResourceDispatchSourceContract(t *testing.T) {
	module := resolveLatestCPASourceOffline(t)
	hostSource := parseLatestCPASource(t, module.Dir, "internal", "pluginhost", "management.go")
	serveResourceTokens := hostSource.nodeTokens(hostSource.mustFunction(t, "ServeResourceHTTP"))
	requireLatestCPASequence(t, serveResourceTokens,
		`if !strings.EqualFold(r.Method, http.MethodGet) { return false }`,
		"case-insensitive resource GET admission")
	requireLatestCPASequence(t, serveResourceTokens,
		`key := managementRouteKey(http.MethodGet, r.URL.Path)`,
		"resource route key normalization")
	requireLatestCPASequence(t, serveResourceTokens,
		`Method: http.MethodGet, Path: r.URL.Path, Headers: cloneHeader(r.Header), Query: cloneValues(r.URL.Query()),`,
		"resource callback header and query preservation")
	requireLatestCPASequenceAbsent(t, serveResourceTokens, `io.ReadAll(`,
		"resource handler request-body read")

	serverSource := parseLatestCPASource(t, module.Dir, "internal", "api", "server.go")
	newServerTokens := serverSource.nodeTokens(serverSource.mustFunction(t, "NewServer"))
	requireLatestCPASequenceBefore(t, newServerTokens,
		`engine.Use(middleware.RequestLoggingMiddleware(requestLogger))`,
		`engine.NoRoute(s.pluginManagementNoRoute)`,
		"request logging middleware before plugin resource NoRoute")

	managementSource := parseLatestCPASource(t, module.Dir, "internal", "api", "server_management.go")
	resourceNoRouteTokens := managementSource.nodeTokens(managementSource.mustFunction(t, "pluginResourceNoRoute"))
	requireLatestCPASequence(t, resourceNoRouteTokens,
		`if s.cfg == nil || s.cfg.Home.Enabled || s.pluginHost == nil { c.AbortWithStatus(http.StatusNotFound); return }`,
		"Home-mode resource disable guard")
	requireLatestCPASequence(t, resourceNoRouteTokens,
		`if s.pluginHost.ServeResourceHTTP(c.Writer, c.Request) { c.Abort(); return }`,
		"plugin resource dispatch")

	responseSource := parseLatestCPASource(t, module.Dir,
		"internal", "api", "middleware", "response_writer.go")
	finalizeTokens := responseSource.nodeTokens(responseSource.mustFunction(t, "Finalize"))
	requireLatestCPASequence(t, finalizeTokens,
		`hasAPIError := hasActionableError(c, finalStatusCode, slicesAPIResponseError)`,
		"actionable HTTP error-only log admission helper")
	requireLatestCPASequence(t, finalizeTokens,
		`forceLog := w.logOnErrorOnly && hasAPIError && !w.logger.IsEnabled()`,
		"disabled logger forced error artifact")

	// CPA v7.2.144 keeps the error-only admission policy in a helper. Keep
	// the semantic guard explicit: API errors always qualify, client-closed
	// requests do not, cancellation only qualifies for an error status, and
	// all remaining HTTP errors qualify. This prevents a source refactor from
	// silently broadening error-only capture while avoiding a brittle inline
	// expression assertion.
	actionableTokens := responseSource.nodeTokens(responseSource.mustFunction(t, "hasActionableError"))
	for marker, description := range map[string]string{
		`if hasActionableAPIResponseErrors(apiErrors) { return true }`:                   "API error admission",
		`if statusCode == clienterror.StatusClientClosedRequest { return false }`:        "client-closed exclusion",
		`if isContextCanceled(c) && statusCode < http.StatusBadRequest { return false }`: "successful cancellation exclusion",
		`return statusCode >= http.StatusBadRequest`:                                     "HTTP error admission",
	} {
		requireLatestCPASequence(t, actionableTokens, marker, description)
	}
}

func TestLatestCPARequestErrorLogManagementSourceContract(t *testing.T) {
	module := resolveLatestCPASourceOffline(t)
	serverSource := parseLatestCPASource(t, module.Dir, "internal", "api", "server_management.go")
	routeTokens := serverSource.nodeTokens(serverSource.mustFunction(t, "registerManagementRoutes"))
	managementMiddleware := `mgmt.Use(s.managementAvailabilityMiddleware(), s.mgmt.Middleware())`
	requestErrorRoute := `mgmt.GET("/request-error-logs", s.mgmt.GetRequestErrorLogs)`
	requireLatestCPASequenceCount(t, routeTokens, requestErrorRoute, 1,
		"GET /request-error-logs route")
	requireLatestCPASequenceBefore(t, routeTokens, managementMiddleware, requestErrorRoute,
		"request-error-logs management middleware wiring")

	handlerSource := parseLatestCPASource(t, module.Dir,
		"internal", "api", "handlers", "management", "handler.go")
	handlerTokens := handlerSource.nodeTokens(handlerSource.mustFunction(t, "Middleware"))
	versionHeader := `c.Header("X-CPA-VERSION", buildinfo.Version)`
	commitHeader := `c.Header("X-CPA-COMMIT", buildinfo.Commit)`
	authenticate := `h.AuthenticateManagementKey(`
	requireLatestCPASequenceCount(t, handlerTokens, versionHeader, 1,
		"X-CPA-VERSION management header")
	requireLatestCPASequenceCount(t, handlerTokens, commitHeader, 1,
		"X-CPA-COMMIT management header")
	requireLatestCPASequenceBefore(t, handlerTokens, versionHeader, authenticate,
		"version header before management authentication")
	requireLatestCPASequenceBefore(t, handlerTokens, commitHeader, authenticate,
		"commit header before management authentication")

	logsSource := parseLatestCPASource(t, module.Dir,
		"internal", "api", "handlers", "management", "logs.go")
	inventoryTokens := logsSource.nodeTokens(logsSource.mustFunction(t, "GetRequestErrorLogs"))
	for marker, description := range map[string]string{
		"Name string `json:\"name\"`":        "name inventory field",
		"Size int64 `json:\"size\"`":         "size inventory field",
		"Modified int64 `json:\"modified\"`": "modified inventory field",
		`if entry.IsDir() { continue }`:      "directory exclusion",
	} {
		requireLatestCPASequence(t, inventoryTokens, marker, description)
	}
	errorLogFilter := `if !strings.HasPrefix(name, "error-") || !strings.HasSuffix(name, ".log") { continue }`
	errorLogAppend := `files = append(files, errorLog{Name: name, Size: info.Size(), Modified: info.ModTime().Unix(),})`
	requireLatestCPASequenceCount(t, inventoryTokens, errorLogFilter, 1,
		"error-*.log inventory filter")
	requireLatestCPASequenceBefore(t, inventoryTokens, errorLogFilter, errorLogAppend,
		"filtered name/size/modified inventory append")
	requireLatestCPASequence(t, inventoryTokens,
		`c.JSON(http.StatusOK, gin.H{"files": files})`,
		"filtered request-error-log inventory response")
}

func resolveLatestCPASourceOffline(t *testing.T) latestResolvedCPAModule {
	t.Helper()
	profile := selectedCPACompatibilityProfile(t)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("locate go tool for offline CPA source resolution: %v", err)
	}
	command := exec.Command(goBinary, "list", "-mod=readonly", "-m", "-json", cpaLatestModulePath)
	command.Env = latestCPAEnvironmentWithOverrides(map[string]string{
		"GOPROXY": "off",
		"GOSUMDB": "off",
		"GOWORK":  "off",
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if errRun := command.Run(); errRun != nil {
		t.Fatalf("resolve cached CPA source with network disabled: %v\nstdout:\n%s\nstderr:\n%s",
			errRun, stdout.String(), stderr.String())
	}

	var module latestResolvedCPAModule
	if errDecode := json.Unmarshal(stdout.Bytes(), &module); errDecode != nil {
		t.Fatalf("decode cached CPA module metadata: %v", errDecode)
	}
	if module.Replace != nil {
		t.Fatal("cached CPA source contract unexpectedly uses a replacement")
	}
	if module.Path != cpaLatestModulePath || module.Version != profile.Version || strings.TrimSpace(module.Dir) == "" {
		t.Fatalf("cached CPA source = %s@%s dir=%q, want %s@%s with a source directory",
			module.Path, module.Version, module.Dir, cpaLatestModulePath, profile.Version)
	}
	if module.Sum != profile.ModuleSum || module.GoModSum != profile.GoModSum {
		t.Fatalf("cached CPA source checksums = module %q go.mod %q, want module %q go.mod %q",
			module.Sum, module.GoModSum, profile.ModuleSum, profile.GoModSum)
	}
	info, errStat := os.Stat(module.Dir)
	if errStat != nil || !info.IsDir() {
		t.Fatalf("cached CPA source directory is unavailable: dir=%q err=%v", module.Dir, errStat)
	}
	t.Logf("CPA source-only request logging contract: %s@%s sum=%s (GOPROXY=off)",
		module.Path, module.Version, module.Sum)
	return module
}

func latestCPAEnvironmentWithOverrides(overrides map[string]string) []string {
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		replaced := false
		for override := range overrides {
			if strings.EqualFold(key, override) {
				replaced = true
				break
			}
		}
		if !replaced {
			environment = append(environment, entry)
		}
	}
	for key, value := range overrides {
		environment = append(environment, key+"="+value)
	}
	return environment
}

func parseLatestCPASource(t *testing.T, moduleDir string, elements ...string) latestCPASourceSyntax {
	t.Helper()
	path := filepath.Join(append([]string{moduleDir}, elements...)...)
	data, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read pinned CPA source %s: %v", path, errRead)
	}
	fset := token.NewFileSet()
	file, errParse := parser.ParseFile(fset, path, data, parser.SkipObjectResolution)
	if errParse != nil {
		t.Fatalf("parse pinned CPA source %s: %v", path, errParse)
	}
	return latestCPASourceSyntax{path: path, data: data, fset: fset, file: file}
}

func (source latestCPASourceSyntax) mustFunction(t *testing.T, name string) *ast.FuncDecl {
	t.Helper()
	var match *ast.FuncDecl
	for _, declaration := range source.file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != name {
			continue
		}
		if match != nil {
			t.Fatalf("%s contains multiple functions named %s", source.path, name)
		}
		match = function
	}
	if match == nil || match.Body == nil {
		t.Fatalf("%s does not define function %s", source.path, name)
	}
	return match
}

func (source latestCPASourceSyntax) mustIfCondition(t *testing.T, node ast.Node, condition string) *ast.IfStmt {
	t.Helper()
	want := latestCPATokens([]byte(condition))
	var match *ast.IfStmt
	ast.Inspect(node, func(current ast.Node) bool {
		statement, ok := current.(*ast.IfStmt)
		if !ok || source.nodeTokens(statement.Cond) != want {
			return true
		}
		if match != nil {
			t.Fatalf("%s contains multiple if conditions matching %q", source.path, condition)
		}
		match = statement
		return true
	})
	if match == nil {
		t.Fatalf("%s does not contain if condition %q", source.path, condition)
	}
	return match
}

func (source latestCPASourceSyntax) allTokens() string {
	return latestCPATokens(source.data)
}

func (source latestCPASourceSyntax) nodeTokens(node ast.Node) string {
	if node == nil {
		return ""
	}
	file := source.fset.File(node.Pos())
	if file == nil {
		return ""
	}
	start := file.Offset(node.Pos())
	end := file.Offset(node.End())
	if start < 0 || end < start || end > len(source.data) {
		return ""
	}
	return latestCPATokens(source.data[start:end])
}

func latestCPATokens(data []byte) string {
	fset := token.NewFileSet()
	file := fset.AddFile("source-contract.go", fset.Base(), len(data))
	var lexer scanner.Scanner
	lexer.Init(file, data, nil, 0)
	tokens := make([]string, 0, len(data)/4)
	for {
		_, current, literal := lexer.Scan()
		if current == token.EOF {
			break
		}
		if current == token.SEMICOLON {
			continue
		}
		if literal == "" {
			literal = current.String()
		} else if current == token.STRING || current == token.CHAR {
			if decoded, err := strconv.Unquote(literal); err == nil {
				literal = current.String() + ":" + decoded
			}
		}
		tokens = append(tokens, literal)
	}
	return strings.Join(tokens, latestCPATokenSeparator)
}

func requireLatestCPASequence(t *testing.T, stream, source, description string) {
	t.Helper()
	requireLatestCPASequenceCountAtLeast(t, stream, source, 1, description)
}

func requireLatestCPASequenceCount(t *testing.T, stream, source string, want int, description string) {
	t.Helper()
	sequence := latestCPATokens([]byte(source))
	if got := latestCPASequenceCount(stream, sequence); got != want {
		t.Fatalf("%s occurrences = %d, want %d", description, got, want)
	}
}

func requireLatestCPASequenceCountAtLeast(t *testing.T, stream, source string, want int, description string) {
	t.Helper()
	sequence := latestCPATokens([]byte(source))
	if got := latestCPASequenceCount(stream, sequence); got < want {
		t.Fatalf("%s occurrences = %d, want at least %d", description, got, want)
	}
}

func requireLatestCPASequenceAbsent(t *testing.T, stream, source, description string) {
	t.Helper()
	requireLatestCPASequenceCount(t, stream, source, 0, description)
}

func requireLatestCPASequenceOnlyWithin(t *testing.T, outer, inner, source, description string) {
	t.Helper()
	sequence := latestCPATokens([]byte(source))
	if got := latestCPASequenceCount(outer, sequence); got != 1 {
		t.Fatalf("%s occurrences in enclosing function = %d, want 1", description, got)
	}
	if got := latestCPASequenceCount(inner, sequence); got != 1 {
		t.Fatalf("%s occurrences inside commercial-mode guard = %d, want 1", description, got)
	}
}

func requireLatestCPASequenceBefore(t *testing.T, stream, first, second, description string) {
	t.Helper()
	firstSequence := latestCPATokens([]byte(first))
	secondSequence := latestCPATokens([]byte(second))
	firstIndex := latestCPASequenceIndex(stream, firstSequence)
	secondIndex := latestCPASequenceIndex(stream, secondSequence)
	if firstIndex < 0 || secondIndex < 0 || firstIndex >= secondIndex {
		t.Fatalf("%s order invalid: first=%d second=%d", description, firstIndex, secondIndex)
	}
}

func latestCPASequenceCount(stream, sequence string) int {
	if sequence == "" {
		return 0
	}
	return strings.Count(latestCPATokenSeparator+stream+latestCPATokenSeparator,
		latestCPATokenSeparator+sequence+latestCPATokenSeparator)
}

func latestCPASequenceIndex(stream, sequence string) int {
	if sequence == "" {
		return -1
	}
	return strings.Index(latestCPATokenSeparator+stream+latestCPATokenSeparator,
		latestCPATokenSeparator+sequence+latestCPATokenSeparator)
}
