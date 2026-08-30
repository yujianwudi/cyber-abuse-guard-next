# syntax=docker/dockerfile:1

# The operator must pass an already audited, repository-qualified digest such
# as registry.example/python@sha256:<64 lowercase hex>.  There is deliberately
# no floating default and no package installation in this build.
ARG KEEPER_BASE_IMAGE
FROM ${KEEPER_BASE_IMAGE}

ARG KEEPER_BASE_IMAGE
ARG KEEPER_SOURCE_SHA256

LABEL cag.current-cpa-audit.contract="cag-current-cpa-host-keeper/v1" \
      cag.current-cpa-audit.source-path="/opt/cag-host-keeper/keeper_fixture.py" \
      cag.current-cpa-audit.source-sha256="${KEEPER_SOURCE_SHA256}" \
      cag.current-cpa-audit.base-image="${KEEPER_BASE_IMAGE}"

USER 0:0
COPY --chown=65532:65532 keeper_fixture.py keeper_fixture.py.sha256 /opt/cag-host-keeper/

RUN python3 -I -S -B -c 'import hashlib,os,pathlib,re,sqlite3,sys; assert sys.version_info >= (3,11), "Python 3.11 or newer is required"; assert sqlite3.sqlite_version_info >= (3,37,0), "SQLite 3.37 or newer is required"; base=sys.argv[1]; expected=sys.argv[2]; source=pathlib.Path("/opt/cag-host-keeper/keeper_fixture.py"); sidecar=pathlib.Path("/opt/cag-host-keeper/keeper_fixture.py.sha256").read_text("ascii").strip().split()[0]; actual=hashlib.sha256(source.read_bytes()).hexdigest(); assert re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}",base), "base image must be digest-pinned"; assert re.fullmatch(r"[0-9a-f]{64}",expected), "source hash build argument is invalid"; assert actual==expected==sidecar, "Keeper source hash mismatch"; data=pathlib.Path("/var/lib/cag-host-keeper"); data.mkdir(parents=True,exist_ok=True); os.chown(data,65532,65532); os.chmod(data,0o700); secrets=pathlib.Path("/run/secrets"); secrets.mkdir(parents=True,exist_ok=True); os.chmod(secrets,0o755); os.chmod(source,0o555); os.chmod(pathlib.Path("/opt/cag-host-keeper/keeper_fixture.py.sha256"),0o444)' "$KEEPER_BASE_IMAGE" "$KEEPER_SOURCE_SHA256"

USER 65532:65532
WORKDIR /opt/cag-host-keeper
EXPOSE 18081

ENTRYPOINT ["python3", "-I", "-S", "-B", "/opt/cag-host-keeper/keeper_fixture.py"]
CMD ["--host", "0.0.0.0", "--port", "18081", "--database", "/var/lib/cag-host-keeper/keeper.sqlite3"]
