# Round 9 counted Mock

This directory is the complete source and Docker build context for the private
upstream used by `scripts/round9_host_evidence.py`. It implements only the
closed Chat Completions, Responses, health, reset, and stats contract described
in `docs/ROUND9_HOST_RUNNER.md`.

The server decodes only the top-level `stream` boolean, discards every request
body when the handler returns, never logs or echoes a body, has no persistence,
and exposes no body-reading debug endpoint. Its sole mutable state is an atomic
request count. The final image is `scratch`, non-root, Linux amd64, and contains
only the static server binary.

Build it through `scripts/round9-build-host-images.sh`; the Host runner rejects
an image without the exact `round9-counted-mock/v1` contract plus Guard source,
candidate revision, release tag, and source-tree labels. Chat streaming ends
with `[DONE]`; Responses streaming ends with a `response.completed` event. The
builder emits an invocation-unique image tag, while the runner resolves and
records the immutable image ID.
