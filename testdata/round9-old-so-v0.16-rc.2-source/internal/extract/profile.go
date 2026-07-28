package extract

// SourceProfile is the bounded, request-independent protocol identity used by
// extraction. Caller-supplied SourceFormat strings must be mapped to this enum
// before crossing into the extractor so they can never reach results, errors,
// counters, or audit metadata.
type SourceProfile uint8

const (
	SourceProfileUnknown SourceProfile = iota
	SourceProfileOpenAI
	SourceProfileOpenAIResponse
	SourceProfileInteractions
	SourceProfileCodexAlphaSearch
	SourceProfileOpenAIImage
	SourceProfileOpenAIVideo
	SourceProfileClaude
	SourceProfileGemini
)

// RequestProfile carries only fixed extraction policy selectors. It never
// contains endpoint paths, model names, field names, or other request data.
type RequestProfile struct {
	Source SourceProfile
}

type multipartFieldClass uint8

const (
	multipartFieldUnknown multipartFieldClass = iota
	multipartFieldText
	multipartFieldMetadata
	multipartFieldFile
)

// classifyMultipartField is intentionally schema-bound and static. Only fields
// proven by the CPA v7.2.95 openai-image path are classified in this round;
// every other multipart schema remains incomplete rather than being guessed.
func classifyMultipartField(profile SourceProfile, name string) multipartFieldClass {
	if profile != SourceProfileOpenAIImage {
		return multipartFieldUnknown
	}
	switch canonicalMultipartField(name) {
	case "prompt", "negative_prompt", "negative-prompt", "negative prompt":
		return multipartFieldText
	case "image", "images", "mask":
		return multipartFieldFile
	case "model", "stream", "n", "size", "quality", "response_format",
		"output_format", "background", "style", "user", "seed", "format",
		"aspect_ratio", "resolution", "input_fidelity", "moderation",
		"output_compression", "partial_images":
		return multipartFieldMetadata
	default:
		return multipartFieldUnknown
	}
}
