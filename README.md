# 🚢 Dredge — Docker Garbage Collector with Brains

[![Build](https://img.shields.io/github/actions/workflow/status/user/dredge/ci.yml?branch=main)](https://github.com/user/dredge/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg)](https://golang.org)

> Smart cleanup for Docker. Like `docker system prune`, but with policies, dependency awareness, and a safety net.

Dredge inspects your Docker daemon, evaluates resources against configurable policies, and removes the ones you don't need — safely, in the right order, with a full audit trail.

---

## How It Works

```
[Docker Daemon]
      |
[Collector] ---> containers, images, volumes, networks
      |
[Policy Engine] ---> evaluate rules + protections + dependency graph
      |
[Planner] ---> ordered execution plan (dry-run output)
      |
[Sweeper] ---> safe deletion with TOCTOU re-check + audit log
```

Each stage is independent. `dredge plan` stops after the Planner. `dredge sweep` runs all four.

---

## Requirements

- Go 1.22+
- Docker Engine running locally (socket at `/var/run/docker.sock` or configurable)
- Linux or macOS

---

## Installation

### Option 1 — Build from source

```bash
git clone https://github.com/user/dredge
cd dredge
make build
# Binary at bin/dredge — copy to PATH:
sudo cp bin/dredge /usr/local/bin/dredge
```

Or with `make install` (copies to `/usr/local/bin` automatically):

```bash
make install
```

### Option 2 — go install

```bash
go install github.com/user/dredge/cmd/dredge@latest
```

### Option 3 — Download pre-built binary

Download from [Releases](https://github.com/user/dredge/releases), extract, and place in your PATH:

```bash
tar -xzf dredge_v0.1.0_linux_amd64.tar.gz
sudo mv dredge /usr/local/bin/
dredge --help
```

---

## Quick Start

### 1. Create config file

```bash
# Copy the example config to your home directory
cp config.example.yaml ~/.dredge.yaml

# Or system-wide
sudo mkdir -p /etc/dredge
sudo cp config.example.yaml /etc/dredge/config.yaml
```

Config is loaded from `~/.dredge.yaml` by default. Override with `--config /path/to/config.yaml`.

### 2. Check what dredge would clean (safe — no changes)

```bash
dredge plan
```

### 3. Review the output, then sweep

```bash
# Interactive — prompts for y/N before deleting
dredge sweep

# Or non-interactive (CI, scripts)
dredge sweep --yes
```

### 4. Protect resources you care about

```bash
# Label a container — dredge will never touch it
docker run -d --label dredge.keep=true --name my-db postgres:16

# Or add to protection.name_patterns in config:
# name_patterns:
#   - "postgres*"
#   - "production-*"
```

### 5. Run as daemon (optional)

```bash
# Cleans every 6h (or configure watch.interval)
dredge watch
```

---

## Commands

### `dredge plan`

Dry-run. Shows what would be removed and why. Makes no changes.

```
$ dredge plan

+--------------------+-------------+--------+----------------------+------------------+
| NAME               | TYPE        | SIZE   | AGE                  | REASON           |
+--------------------+-------------+--------+----------------------+------------------+
| old-worker         | container   | 12 MB  | 3 days               | exited > 24h     |
| build-cache        | container   | 4 MB   | 5 days               | exited > 24h     |
| <none>:<none>      | image       | 220 MB | 8 days               | dangling image   |
| data-migration-vol | volume      | 0 B    | 14 days              | orphaned volume  |
+--------------------+-------------+--------+----------------------+------------------+
  4 resources  |  236 MB recoverable
```

### `dredge sweep`

Executes cleanup. Requires `--yes` or interactive confirmation.

```bash
# Interactive (prompts for y/N)
dredge sweep

# Non-interactive (scripts, CI)
dredge sweep --yes
```

Deletion order is always: **containers → images → volumes → networks**. This prevents cascade failures from dangling references.

### `dredge stats`

Read-only. Shows current resource usage. Never modifies anything.

```
$ dredge stats

Containers:  12 total  (3 running, 7 exited, 2 created)
Images:      24 total  (4 dangling, 20 tagged)
Volumes:     8 total
Networks:    5 total   (3 default, 2 custom)

Disk Usage:
  Images:     4.2 GB
  Containers: 320 MB
  Volumes:    1.1 GB
  Total:      5.6 GB
```

### `dredge watch`

Daemon mode. Runs plan+sweep automatically at a configured interval.

```bash
# Use interval from config (default: 6h)
dredge watch

# Override interval
dredge watch --interval 30m
```

Responds to `SIGTERM`/`SIGINT` with graceful shutdown (completes the current deletion, does not start new ones).

---

## Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--config <file>` | Config file path | `~/.dredge.yaml`, `/etc/dredge/config.yaml` |
| `--socket <path>` | Docker socket path | from config |
| `--log-level <lvl>` | `debug`, `info`, `warn`, `error` | `info` |
| `--format <fmt>` | `table` or `json` | `table` |

---

## Configuration

```yaml
# ~/.dredge.yaml

# Docker connection
docker:
  socket: "/var/run/docker.sock"
  timeout: "30s"

# Cleanup policies
policies:
  containers:
    - status: "exited"
      older_than: "24h"
    - status: "created"
      older_than: "48h"
    - status: "dead"
      older_than: "0s"

  images:
    dangling: true
    unused_older_than: "168h"   # 7 days

  volumes:
    orphaned: true

  networks:
    unused: true

# Protection — these resources are NEVER deleted
protection:
  label: "dredge.keep=true"
  name_patterns:
    - "postgres*"
    - "redis*"
    - "production-*"
    - "*-db"

# Watch mode (daemon)
watch:
  interval: "6h"
  # cron: "0 */6 * * *"

# Logging
logging:
  level: "info"
  format: "json"
  output: "stderr"
```

### Marking a Resource as Protected

Add the label `dredge.keep=true` to any resource. Dredge will never touch it.

```bash
docker run -d --label dredge.keep=true --name my-db postgres:16
docker volume create --label dredge.keep=true my-data
```

Config also supports glob patterns on names:

```yaml
protection:
  name_patterns:
    - "production-*"
    - "*-db"
```

---

## Safety Features

Dredge implements 10 independent layers of protection. A bug in any single layer is caught by the others.

| Layer | What It Does |
|-------|--------------|
| **1. Docker Socket Safety** | Socket path is configurable, never hardcoded. All operations have a timeout. |
| **2. Running Container Protection** | Containers with state `running` are NEVER touched. Hardcoded — not configurable. |
| **3. Label Protection (3 layers)** | `dredge.keep=true` is checked independently by the policy engine, planner, AND sweeper. |
| **4. Dependency Graph** | Images are not deleted if any referencing container is kept. |
| **5. Deletion Order** | Containers before images before volumes before networks — prevents cascade failures. |
| **6. Dry-Run Parity** | `plan` and `sweep` use the identical code path. What plan shows is exactly what sweep removes. |
| **7. Confirmation Required** | `sweep` without `--yes` requires interactive confirmation (default: N). Piped stdin without `--yes` is an error. |
| **8. TOCTOU Defense** | Before each deletion, the resource is re-inspected. A container that started between plan and sweep is skipped. |
| **9. Config Validation** | Unknown YAML fields, negative durations, invalid statuses — all rejected immediately at startup. |
| **10. Audit Log** | Every deletion logged as structured JSON: type, ID, name, size, reason, timestamp. No secrets logged. |

### FAQ

**Will this delete my running containers?**
Never. Running containers are protected by a hardcoded check in the policy engine that cannot be overridden by any configuration.

**What if I delete something I needed?**
Containers and images: gone. Volumes: data is gone permanently. This is why `dredge plan` exists — always review it first. If a resource matters, add `dredge.keep=true` to it.

**What happens if a deletion fails?**
Dredge logs the error and continues with the next resource (fail-forward). A single failure never aborts the entire sweep.

**Are `bridge`, `host`, and `none` networks safe?**
Yes. Default Docker networks are always protected, regardless of your network cleanup policy.

**Can I use it in CI/CD?**
Yes. Use `dredge sweep --yes` for non-interactive execution.

---

## Dependency Graph

Before any deletion, dredge builds a map of image → referencing containers. If any referencing container is kept, the image is kept too — even if the image would otherwise qualify for deletion.

```
Image: my-app:v1.2  <--- referenced by: [worker-1 (exited, kept by label), batch-job (exited, to delete)]
                                                  ^
                                          kept container → image is protected
```

This prevents the situation where you delete an image that a container still needs when it next starts.

---

## Watch Mode as a Daemon

### systemd Unit File

```ini
# /etc/systemd/system/dredge.service
[Unit]
Description=Dredge Docker Garbage Collector
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/dredge watch --config /etc/dredge/config.yaml
Restart=on-failure
RestartSec=30s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now dredge
journalctl -u dredge -f
```

### Docker Compose

```yaml
services:
  dredge:
    image: ghcr.io/user/dredge:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./dredge.yaml:/etc/dredge/config.yaml:ro
    command: watch
    restart: unless-stopped
```

---

## Output Formats

All commands support `--format json` for structured output suitable for pipelines:

```bash
dredge plan --format json | jq '.deletions[] | select(.type == "volume")'
dredge stats --format json | jq '.disk_usage.total'
```

---

## Building

```bash
# Requirements: Go 1.22+, Docker (for integration tests)

make build            # build to bin/dredge
make test             # unit tests
make test-integration # integration tests (requires running Docker)
make test-all         # unit + integration
make lint             # golangci-lint
make vet              # go vet
make fmt              # gofmt
```

---

## Contributing

1. Fork and create a branch: `git checkout -b feat/my-feature`
2. Follow the existing code style (`make fmt && make vet`)
3. Add tests — unit tests for logic, integration tests for Docker interactions
4. Verify security checklist in `CLAUDE.md` before opening a PR
5. Open a pull request

---

## License

MIT — see [LICENSE](LICENSE).
