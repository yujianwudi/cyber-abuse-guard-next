FROM docker.io/library/golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b AS builder

WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -buildvcs=false -trimpath -ldflags='-s -w' -o /out/round8-counted-mock .

FROM scratch
LABEL io.cyber-abuse-guard.round8.mock-contract="round8-counted-mock/v1"
COPY --from=builder --chown=65532:65532 /out/round8-counted-mock /round8-counted-mock
USER 65532:65532
EXPOSE 18080
ENTRYPOINT ["/round8-counted-mock"]
