# Refresh ownership prerequisite

Managed releases are opt-in via `MMC_RELEASE_LOCK_FILE` (absolute shared local
lock path) and `MMC_RELEASE_CONTROL_TOKEN` (at least 32 bytes). Supplying only one
fails startup. Standalone CPA behavior stays unchanged when both are absent.
The service requires standalone FileTokenStore and rejects Home mode. Managed
credentials are limited to Codex and linked `bps` accounts; other rotating OAuth
providers fail startup/registration rather than bypass ownership through a
provider-specific credential mint path. Nonrotating configured API keys remain
supported.

Legacy file records whose exact provider is `free` are retained unchanged and
remain visible to management, but are not Codex free-plan accounts. In managed
mode these records have no models and no usable inference/refresh executor.
They must be file-backed, have no runtime or routing attributes (`base_url`,
`api_key`, `compat_name`, `provider_key`), and must not have an active named
OpenAI-compatibility configuration or loaded plugin provider mapping for `free`.
Startup, activation and configuration updates reject conflicting mappings.
This preserves existing inert records; it does not enable or convert them.

The integrated service creates an inactive owner before starting refresh workers,
gates Manager persistence and FileTokenStore Save/Delete, and wraps the HTTP
server. Control routes are mounted under `/__mmc_release/`:

- `GET /status`: owner, accepting, in-flight refresh count.
- `POST /activate`: acquire the exclusive OS lock and admit refreshes.
- `POST /quiesce` (or `/drain`): stop inference admission and wait up to 30 seconds
  for credential writes/refreshes. Existing inference and plugin executions remain
  alive and are counted separately for safe stop.
- `GET /health`: unauthenticated readiness of the standby control listener only.

All except health require `Authorization: Bearer <secret>`. New owners start inactive. An
activation failure is a conflict. A quiesce timeout is also a conflict and keeps
the lock held; retry rather than switching token ownership on a timer. Gate
admission encompasses background refresh, synchronous refresh, and the durable
save. Lock files must never be removed/replaced, and their parent directories
must be trusted, private, and consistently mounted in every release container.
Network filesystems are not supported by this operational contract.

Status contains HTTP, plugin, raw upstream active counts and `safe_to_stop`. Raw
native streams remain counted after client cancellation until their producer
channel closes, after native response-body cleanup. There is no timeout that
turns an unconfirmed upstream cleanup into a safe-stop claim. Ownership can
transfer while old inference streams continue; safe stop requires those streams
and plugin activities to end. Reactivating a previously drained instance requires
its old executions to finish before reloading credentials. Never expose control
paths through the public reverse proxy.

Activation holds the OS lock while Manager.Load replaces its credential map from
the durable store, then opens admission. Reload and watcher application share the
auth-update mutex; queued watcher snapshots are reread from the durable store so
old tokens cannot replace fresh tokens or resurrect deleted credentials.
Legacy management routes are restricted
to synchronous auth-files CRUD, models, status/fields and api-call used by the
platform; their complete handlers hold write ownership. Async OAuth/login and all
other legacy routes and the v8 management surface are denied in managed mode.
The exact GET `/v0/management/plugins/oai-basispoints-cpa/status` is allowed for
authenticated aggregate-only plugin metrics; no public resource is registered.
Do not enable alternate token
stores or CLI login processes against this shared directory.

First migration from an unmodified legacy CPA must drain and stop that instance
before any new instance starts owning its credentials. This bootstrap has a brief
admission gap and is intentionally not implemented by the rolling controller.

Rollback uses the same quiesce, latest-credential reload, activate sequence in
reverse. No copies of old rotating refresh tokens may be restored.

## Controller

`python3 scripts/cpa-release.py --config /private/cpa-release.json status`
supports `switch INSTANCE`, `rollback`, and `stop-old`. Configuration contains
absolute `state_file`, `upstream_file`, `token_file`, `nginx_container`,
`initial_active`, and `instances` mapping each name to `endpoint` (explicit
loopback HTTP origin), `upstream` (host:port), and `container`. Nginx must include
the managed file and proxy inference to `http://mmc_cpa_active`; mount the parent
configuration directory, not a single file that would retain a replaced inode.

The controller locks its journal, verifies gated endpoints, quiesces old writes,
activates/reloads the candidate, atomically updates the upstream include, runs
`nginx -t`, and reloads gracefully. Existing streams remain on old workers. There
is a short admission gap during ownership transfer; do not configure arbitrary
inference retries to conceal it. `stop-old` verifies all safe-stop fields before
stopping the explicitly configured container. Room/global feature settings are
never changed.

A pending journal is deliberately retained on failure. Fix the reported cause
and rerun the same `switch INSTANCE` to resume. The controller will not stop an
instance or launch a different cutover while a switch is pending. In particular,
an Nginx failure after ownership transfer can leave the old route rejecting new
requests until the same switch is completed. Inspect status rather than guessing
which instance owns tokens. The script does not start stopped rollback containers;
start the previous image in managed standby mode before invoking rollback.
