#!/bin/sh
set -eu

compose_file=compose.dev.yaml
project=netanchor
runtime=${CONTAINER_RUNTIME:-podman}

if ! command -v "$runtime" >/dev/null 2>&1; then
  echo "Container runtime '$runtime' is unavailable on ataltpr06" >&2
  exit 1
fi
if ! "$runtime" compose version >/dev/null 2>&1; then
  echo "No working '$runtime compose' provider on ataltpr06; install podman-compose or a compatible Compose provider" >&2
  exit 1
fi
if ! "$runtime" compose -f "$compose_file" -p "$project" config >/dev/null; then
  echo "Development Compose configuration is invalid or provider-incompatible; app was not stopped" >&2
  exit 1
fi
if ! "$runtime" volume inspect netanchor-data >/dev/null 2>&1; then
  echo "Required external volume netanchor-data does not exist; refusing to create or delete data automatically" >&2
  exit 1
fi
volume_name=$("$runtime" volume inspect --format '{{.Name}}' netanchor-data 2>/dev/null) || {
  echo 'Could not inspect ownership/name of netanchor-data; app was not stopped' >&2
  exit 1
}
[ "$volume_name" = netanchor-data ] || { echo "Unexpected data volume '$volume_name'; expected netanchor-data" >&2; exit 1; }

# A legacy container may have been created with `podman run`. Only adopt it if
# its /data mount is exactly the named volume the Compose project will preserve.
exists=0
if "$runtime" container exists netanchor; then exists=1; fi
if [ "$exists" -eq 1 ]; then
  details=$("$runtime" inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}} {{.Name}} {{.Source}}{{end}}{{end}}' netanchor)
  expected=netanchor-data
  case "$details" in
    "volume $expected "*) ;;
    *) echo "Refusing to replace legacy netanchor: /data mount is '$details', expected named volume '$expected'. Inspect it and migrate data manually." >&2; exit 1 ;;
  esac
fi

# Complete the build before stopping/replacing a known running instance.
"$runtime" compose -f "$compose_file" -p "$project" build netanchor
if [ "$exists" -eq 1 ]; then
  "$runtime" stop netanchor
  "$runtime" rm netanchor
fi
"$runtime" compose -f "$compose_file" -p "$project" up -d --force-recreate

attempt=0
while [ "$attempt" -lt 30 ]; do
  state=$("$runtime" inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' netanchor 2>/dev/null || true)
  case "$state" in healthy) echo 'Development deployment is healthy'; exit 0;; esac
  case "$state" in exited|dead) break;; esac
  attempt=$((attempt + 1))
  sleep 2
done
echo "Development deployment did not become healthy (state: ${state:-unknown}); recent logs:" >&2
"$runtime" logs --tail 80 netanchor >&2 || true
exit 1
