package extract

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"
)

// ExtractRequest dispatches a CPA request body by Content-Type and performs
// provider-aware JSON extraction or bounded multipart extraction. Content
// parse failures are represented in Result.IncompleteReasons; the returned
// error is reserved for invalid extractor configuration.
func ExtractRequest(body []byte, headers http.Header, limits Limits) (Result, error) {
	return ExtractProfiledRequest(body, headers, RequestProfile{Source: SourceProfileUnknown}, limits)
}

// ExtractProfiledRequest dispatches a request with a fixed caller-supplied
// protocol profile. JSON extraction remains format-tolerant; multipart text is
// accepted only when the selected profile explicitly classifies the field.
func ExtractProfiledRequest(body []byte, headers http.Header, profile RequestProfile, limits Limits) (Result, error) {
	collector := &collectingChunkSink{}
	result, err := ScanProfiledRequest(body, headers, profile, limits, collector)
	if err != nil {
		return Result{}, err
	}
	collector.apply(&result)
	result.BytesScanned = result.TextBytesScanned
	return result, nil
}

// ExtractUntrustedRequest is the conservative request-level entry point for a
// source whose JSON schema is unknown. Multipart field handling is identical
// because file detection cannot rely on provider trust.
func ExtractUntrustedRequest(body []byte, headers http.Header, limits Limits) (Result, error) {
	collector := &collectingChunkSink{}
	result, err := ScanUntrustedRequest(body, headers, limits, collector)
	if err != nil {
		return Result{}, err
	}
	collector.apply(&result)
	result.BytesScanned = result.TextBytesScanned
	return result, nil
}

func extractRequest(body []byte, headers http.Header, profile RequestProfile, limits Limits, initial contextKind, roleIndex bool) (Result, error) {
	normalized, err := limits.normalized()
	if err != nil {
		return Result{}, err
	}
	result := newRequestResult(body, normalized)
	if len(body) > normalized.MaxRawBytes {
		result.addIncomplete(IncompleteRawBodyLimit)
		result.finish()
		return result, nil
	}

	if unsupportedContentEncoding(headers) {
		result.addIncomplete(IncompleteUnsupportedContentEncoding)
		result.finish()
		return result, nil
	}

	contentTypes := headerValues(headers, "Content-Type")
	if len(contentTypes) > 1 {
		result.addIncomplete(IncompleteUnsupportedMediaType)
		result.finish()
		return result, nil
	}
	if len(contentTypes) == 0 || strings.TrimSpace(contentTypes[0]) == "" {
		if obviousJSON(body) {
			return extractRequestJSON(body, normalized, initial, roleIndex), nil
		}
		result.addIncomplete(IncompleteUnsupportedMediaType)
		result.finish()
		return result, nil
	}

	mediaType, params, parseErr := mime.ParseMediaType(contentTypes[0])
	if parseErr != nil {
		result.addIncomplete(IncompleteUnsupportedMediaType)
		result.finish()
		return result, nil
	}
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	switch {
	case isJSONMediaType(mediaType):
		if !supportedJSONCharset(params) {
			result.addIncomplete(IncompleteUnsupportedMediaType)
			result.finish()
			return result, nil
		}
		return extractRequestJSON(body, normalized, initial, roleIndex), nil
	case mediaType == "multipart/form-data":
		// CPA image handlers can transform ingress multipart to a complete JSON
		// execution body while retaining the original Content-Type. Accept only a
		// syntactically complete object/array; malformed JSON continues through the
		// multipart parser and can never become a complete inspection.
		if profile.Source != SourceProfileUnknown && obviousCompleteJSON(body) {
			return extractTransformedMultipartJSON(body, profile, normalized), nil
		}
		boundary, ok := params["boundary"]
		if !ok || boundary == "" {
			result.addIncomplete(IncompleteMultipartParseError)
			result.finish()
			return result, nil
		}
		if len(boundary) > normalized.MaxMultipartBoundaryBytes {
			result.addIncomplete(IncompleteMultipartBoundaryLimit)
			result.finish()
			return result, nil
		}
		return extractMultipart(body, boundary, profile, normalized), nil
	default:
		result.addIncomplete(IncompleteUnsupportedMediaType)
		result.finish()
		return result, nil
	}
}

func extractRequestJSON(body []byte, limits Limits, initial contextKind, roleIndex bool) Result {
	result := newRequestResult(body, limits)
	// CPA model requests are JSON objects or arrays. A valid scalar cannot be
	// interpreted as a supported provider request and must not become a silent
	// complete allow in strict mode.
	if !obviousJSON(body) || !utf8.Valid(body) {
		result.addIncomplete(IncompleteParseError)
		result.ParseError = ErrInvalidJSON.Error()
		result.finish()
		return result
	}
	x := extractor{
		limits:      limits,
		result:      &result,
		requestMode: true,
	}
	if err := x.walkJSON(body, initial, 0, false); err != nil {
		result.addIncomplete(IncompleteParseError)
		result.ParseError = ErrInvalidJSON.Error()
		result.BytesScanned = result.TextBytesScanned
		result.finish()
		return result
	}

	// The RawMessage role index is a second parse. Skip it for raw bodies larger
	// than the semantic text budget, which avoids duplicating large opaque media
	// allocations. Parts remain conservative and fully classifiable.
	if roleIndex && result.IsComplete() && len(body) <= limits.MaxScanBytes {
		segments, roleAware, roleTruncated := extractRoleSegments(body, limits)
		if roleTruncated {
			result.addIncomplete(IncompleteTextPartLimit)
		}
		if roleAware {
			result.Segments = segments
			result.RoleAware = true
		}
	}
	result.BytesScanned = result.TextBytesScanned
	result.finish()
	return result
}

func newRequestResult(body []byte, limits Limits) Result {
	observed := len(body)
	if observed > limits.MaxRawBytes {
		observed = limits.MaxRawBytes
	}
	return Result{
		Parts:            make([]string, 0, minInt(8, limits.MaxTextParts)),
		Completeness:     CompletenessComplete,
		RawBytesObserved: int64(observed),
	}
}

func isJSONMediaType(mediaType string) bool {
	if mediaType == "application/json" {
		return true
	}
	return strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json")
}

func supportedJSONCharset(params map[string]string) bool {
	charset, present := params["charset"]
	if !present || strings.TrimSpace(charset) == "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(charset), "utf-8")
}

func obviousJSON(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func obviousCompleteJSON(body []byte) bool {
	return obviousJSON(body) && json.Valid(body)
}

func unsupportedContentEncoding(headers http.Header) bool {
	values := headerValues(headers, "Content-Encoding")
	for _, value := range values {
		for _, encoding := range strings.Split(value, ",") {
			encoding = strings.TrimSpace(encoding)
			if encoding != "" && !strings.EqualFold(encoding, "identity") {
				return true
			}
		}
	}
	return false
}

func headerValues(headers http.Header, name string) []string {
	var result []string
	for key, values := range headers {
		if strings.EqualFold(strings.TrimSpace(key), name) {
			result = append(result, values...)
		}
	}
	return result
}
