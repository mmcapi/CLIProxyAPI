#!/usr/bin/env python3
"""Controlled CPA ownership transfer and Nginx cutover (Linux production)."""
import argparse
import json
import os
import pathlib
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request


def atomic_write(path, data):
    path = pathlib.Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".cpa-release-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            parent = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_config(path):
    cfg = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    for field in ("state_file", "upstream_file", "token_file"):
        if not pathlib.Path(cfg[field]).is_absolute():
            raise ValueError(field + " must be absolute")
    for name, instance in cfg["instances"].items():
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
            raise ValueError("invalid instance name")
        endpoint = urllib.parse.urlsplit(instance["endpoint"])
        if endpoint.scheme != "http" or endpoint.hostname not in ("127.0.0.1", "localhost", "::1") or endpoint.path or endpoint.query or endpoint.fragment or endpoint.username or not endpoint.port:
            raise ValueError("control endpoint must be an explicit loopback HTTP origin")
        if not re.fullmatch(r"(?:127\.0\.0\.1|[a-zA-Z0-9_-]+):[0-9]{1,5}", instance["upstream"]):
            raise ValueError("invalid upstream address")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", instance["container"]):
            raise ValueError("invalid instance container")
    if cfg["initial_active"] not in cfg["instances"]:
        raise ValueError("initial active instance absent")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", cfg["nginx_container"]):
        raise ValueError("invalid nginx container")
    return cfg


class ControlError(RuntimeError):
    pass


class Release:
    def __init__(self, cfg, request=None, command=None):
        self.cfg = cfg
        self.request = request or self._request
        self.command = command or self._command
        path = pathlib.Path(cfg["state_file"])
        self.state = json.loads(path.read_text()) if path.exists() else {"active": cfg["initial_active"], "previous": None, "pending": None}

    def _request(self, name, action):
        token = pathlib.Path(self.cfg["token_file"]).read_text().strip()
        if len(token) < 32:
            raise ControlError("release token is missing or too short")
        url = self.cfg["instances"][name]["endpoint"] + "/__mmc_release/" + action
        req = urllib.request.Request(url, data=None if action == "status" else b"", headers={"Authorization": "Bearer " + token}, method="GET" if action == "status" else "POST")
        try:
            # Disable environment proxies and redirects: secrets stay on the configured listener.
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            with opener.open(req, timeout=35) as response:
                return json.load(response)
        except (urllib.error.URLError, ValueError) as exc:
            raise ControlError("control operation failed: " + name + "/" + action) from exc

    @staticmethod
    def _command(args):
        result = subprocess.run(args, capture_output=True, text=True)
        if result.returncode:
            raise ControlError("command failed: " + " ".join(args))

    def save(self):
        atomic_write(self.cfg["state_file"], json.dumps(self.state, sort_keys=True) + "\n")

    def status(self):
        results = {}
        for name in self.cfg["instances"]:
            try:
                results[name] = self.request(name, "status")
            except ControlError:
                results[name] = {"unavailable": True}
        return {"release": self.state, "instances": results}

    def switch(self, target):
        if target not in self.cfg["instances"]:
            raise ControlError("unknown target")
        pending = self.state.get("pending")
        if pending and pending["to"] != target:
            raise ControlError("resume pending switch before another operation")
        current = pending["from"] if pending else self.state["active"]
        if current == target:
            raise ControlError("target already active")
        # A legacy unmodified CPA does not expose status; bootstrap must be separate.
        old = self.request(current, "status")
        new = self.request(target, "status")
        if not pending and (not old["refresh"]["owner"] or not old["admitting"] or new["refresh"]["owner"] or new["admitting"]):
            raise ControlError("active/candidate ownership preflight failed")
        if not pending:
            self.state["pending"] = {"from": current, "to": target}
            self.save()
        relinquished = self.request(current, "quiesce")
        if relinquished["refresh"]["owner"] or relinquished["refresh"]["in_flight"] or relinquished["admitting"]:
            raise ControlError("old credential owner has not quiesced")
        activated = self.request(target, "activate")
        if not activated["refresh"]["owner"] or not activated["admitting"]:
            raise ControlError("candidate activation failed")
        route = "upstream mmc_cpa_active { server " + self.cfg["instances"][target]["upstream"] + "; }\n"
        route_path = pathlib.Path(self.cfg["upstream_file"])
        previous_route = route_path.read_text(encoding="utf-8")
        atomic_write(route_path, route)
        try:
            self.command(["docker", "exec", self.cfg["nginx_container"], "nginx", "-t"])
            self.command(["docker", "exec", self.cfg["nginx_container"], "nginx", "-s", "reload"])
        except ControlError:
            atomic_write(route_path, previous_route)
            # Keep pending state. Rerunning the same switch is idempotent and
            # completes the route after fixing Nginx; never guess token rollback.
            raise
        self.state.update(active=target, previous=current, pending=None)
        self.save()

    def rollback(self):
        if self.state.get("pending"):
            raise ControlError("resume pending switch before rollback")
        previous = self.state.get("previous")
        if not previous:
            raise ControlError("no previous instance")
        self.switch(previous)

    def stop_old(self):
        if self.state.get("pending"):
            raise ControlError("pending switch prevents stop")
        previous = self.state.get("previous")
        if not previous or previous == self.state["active"]:
            raise ControlError("no old instance")
        status = self.request(previous, "status")
        if not status.get("safe_to_stop") or status["admitting"] or status["http_active"] or status["plugin_active"] or status["upstream_active"] or status["refresh"]["owner"] or status["refresh"]["in_flight"]:
            raise ControlError("old instance has not safely drained")
        self.command(["docker", "stop", self.cfg["instances"][previous]["container"]])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("action", choices=("status", "switch", "rollback", "stop-old"))
    parser.add_argument("target", nargs="?")
    args = parser.parse_args()
    cfg = load_config(args.config)
    import fcntl  # Linux production only; OS lock is retained for the entire command.
    with open(cfg["state_file"] + ".lock", "a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        release = Release(cfg)
        if args.action == "status":
            print(json.dumps(release.status(), sort_keys=True))
        elif args.action == "switch":
            release.switch(args.target)
        elif args.action == "rollback":
            release.rollback()
        else:
            release.stop_old()


if __name__ == "__main__":
    try:
        main()
    except (ControlError, ValueError, KeyError, OSError) as error:
        raise SystemExit(str(error))
