package extract

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

const rootFieldPath = "$"

func appendObjectFieldPath(parent, key string) string {
	if parent == "" {
		parent = rootFieldPath
	}
	return parent + "/" + strconv.Quote(key)
}

func appendArrayFieldPath(parent string, index int) string {
	if parent == "" {
		parent = rootFieldPath
	}
	return parent + "/" + strconv.Itoa(index)
}

// structuralFieldPathHash deliberately excludes request text. The source
// profile is included so the same spelling in different protocol envelopes
// cannot accidentally become a cross-provider identity.
func structuralFieldPathHash(source SourceProfile, path string) string {
	if path == "" {
		path = rootFieldPath
	}
	digest := sha256.Sum256([]byte(strconv.Itoa(int(source)) + "\x00" + path))
	// 128 bits is ample for request-local boundary identity while avoiding the
	// per-chunk overhead of a full SHA-256 rendering.
	return hex.EncodeToString(digest[:16])
}

func multipartFieldPath(source SourceProfile, name string, ordinal int) string {
	return appendArrayFieldPath(appendObjectFieldPath(rootFieldPath, name), ordinal)
}
