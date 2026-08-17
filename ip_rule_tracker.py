#!/usr/bin/env python3
"""
Track a remote UniFi network's public IP and keep a local UniFi controller's
port forward rules restricted to that IP.

Run on a cron schedule, e.g. every 5 minutes:
    */5 * * * * /path/to/venv/bin/python /path/to/ip_rule_tracker.py \
        --config /path/to/config.yaml >> /path/to/cron_errors.log 2>&1
"""

import argparse
import contextlib
import fcntl
import json
import logging
import logging.handlers
import sys
from pathlib import Path

import requests
import yaml

DEFAULT_TIMEOUT = 10


class ConfigError(RuntimeError):
    pass


class RemoteApiError(RuntimeError):
    pass


class LocalApiError(RuntimeError):
    pass


class RemoteSiteClient:
    """Reads the current WAN external IP from the UniFi Site Manager API."""

    def __init__(self, base_url, api_key, timeout=DEFAULT_TIMEOUT):
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"X-API-KEY": api_key, "Accept": "application/json"}
        )

    def get_external_ip(self, host_id="", wan_key="WAN"):
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise RemoteApiError(f"request to remote API failed: {exc}") from exc

        try:
            hosts = resp.json()["data"]
        except (ValueError, KeyError) as exc:
            raise RemoteApiError(f"unexpected remote API response shape: {exc}") from exc

        if not hosts:
            raise RemoteApiError("remote API returned no hosts")

        if host_id:
            host = next(
                (h for h in hosts if h.get("id") == host_id or h.get("hostId") == host_id),
                None,
            )
            if host is None:
                raise RemoteApiError(f"host_id '{host_id}' not found in remote API response")
        else:
            host = hosts[0]

        wans = host.get("reportedState", {}).get("wans", [])
        wan = next((w for w in wans if w.get("type") == wan_key), None)
        if wan is None:
            raise RemoteApiError(
                f"WAN type '{wan_key}' not present; available types: "
                f"{[w.get('type') for w in wans]}"
            )

        ip = wan.get("ipv4")
        if not ip:
            raise RemoteApiError(f"ipv4 missing for WAN '{wan_key}'")

        return ip


class LocalControllerClient:
    """Reads/writes port forward rules on a local UniFi controller."""

    def __init__(self, base_url, api_key, site, verify_ssl=True, timeout=DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.site = site
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"X-API-KEY": api_key, "Accept": "application/json"}
        )
        self.session.verify = verify_ssl

    def _portforward_url(self, rule_id=None):
        url = f"{self.base_url}/proxy/network/api/s/{self.site}/rest/portforward"
        if rule_id:
            url = f"{url}/{rule_id}"
        return url

    def list_port_forwards(self):
        try:
            resp = self.session.get(self._portforward_url(), timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise LocalApiError(f"failed to list port forward rules: {exc}") from exc
        try:
            return resp.json()["data"]
        except (ValueError, KeyError) as exc:
            raise LocalApiError(f"unexpected local API response shape: {exc}") from exc

    def create_port_forward(self, payload):
        try:
            resp = self.session.post(
                self._portforward_url(), json=payload, timeout=self.timeout
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise LocalApiError(
                f"failed to create port forward rule '{payload.get('name')}': {exc}"
            ) from exc

    def update_port_forward(self, rule_id, payload):
        try:
            resp = self.session.put(
                self._portforward_url(rule_id), json=payload, timeout=self.timeout
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise LocalApiError(
                f"failed to update port forward rule '{payload.get('name')}': {exc}"
            ) from exc


def load_config(path):
    try:
        with open(path, "r") as fh:
            config = yaml.safe_load(fh)
    except FileNotFoundError as exc:
        raise ConfigError(
            f"config file not found: {path} (copy config.example.yaml to get started)"
        ) from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file is not valid YAML: {exc}") from exc

    for section in ("remote", "local", "port_forward_rules"):
        if section not in config:
            raise ConfigError(f"config is missing required section '{section}'")

    if not config["port_forward_rules"]:
        raise ConfigError("config.port_forward_rules is empty - nothing to manage")

    return config


def setup_logging(log_file, max_bytes, backup_count, verbose):
    logger = logging.getLogger("ip_rule_tracker")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count
    )
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    )
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console_handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(console_handler)

    return logger


def read_state(state_file):
    path = Path(state_file)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def write_state(state_file, state):
    path = Path(state_file)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(state, indent=2))
    tmp_path.replace(path)


def build_desired_rule(template, source_ip):
    rule = dict(template)
    rule["src"] = source_ip
    return rule


def rule_matches(existing, desired):
    fields = ("enabled", "pfwd_interface", "proto", "dst_port", "fwd", "fwd_port", "log", "src")
    return all(existing.get(field) == desired.get(field) for field in fields)


def sync_port_forward_rules(local_client, rule_templates, source_ip, logger, dry_run):
    existing_rules = {r.get("name"): r for r in local_client.list_port_forwards()}
    changed = False
    errors = []

    for template in rule_templates:
        name = template.get("name")
        if not name:
            errors.append("rule template missing 'name' field, skipping")
            logger.error(errors[-1])
            continue

        desired = build_desired_rule(template, source_ip)
        existing = existing_rules.get(name)

        if existing and rule_matches(existing, desired):
            logger.debug("rule '%s' already up to date", name)
            continue

        action = "update" if existing else "create"
        if dry_run:
            logger.info("[dry-run] would %s rule '%s' with src=%s", action, name, desired["src"])
            changed = True
            continue

        try:
            if existing:
                local_client.update_port_forward(existing["_id"], desired)
            else:
                local_client.create_port_forward(desired)
            logger.info("%sd rule '%s' -> src=%s", action, name, desired["src"])
            changed = True
        except LocalApiError as exc:
            errors.append(str(exc))
            logger.error(str(exc))

    return changed, errors


@contextlib.contextmanager
def single_instance_lock(lock_path, logger):
    lock_file = open(lock_path, "w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        logger.warning("another run appears to be in progress (%s locked), exiting", lock_path)
        lock_file.close()
        sys.exit(4)
    try:
        yield
    finally:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", default=str(Path(__file__).with_name("config.yaml")),
        help="path to config.yaml (default: config.yaml next to this script)",
    )
    parser.add_argument("--dry-run", action="store_true", help="log intended changes without calling the local API")
    parser.add_argument("--force", action="store_true", help="re-apply rules even if the remote IP hasn't changed")
    parser.add_argument("--verbose", action="store_true", help="also log debug-level detail, including no-op checks")
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1

    config_dir = Path(args.config).parent
    state_file = config_dir / config.get("state_file", "state.json")
    log_file = config_dir / config.get("log_file", "ip_rule_tracker.log")
    lock_file = state_file.with_suffix(".lock")

    logger = setup_logging(
        log_file,
        config.get("log_max_bytes", 1_048_576),
        config.get("log_backup_count", 3),
        args.verbose,
    )

    with single_instance_lock(lock_file, logger):
        return run(args, config, state_file, logger)


def run(args, config, state_file, logger):
    remote_cfg = config["remote"]
    local_cfg = config["local"]

    remote_client = RemoteSiteClient(remote_cfg["base_url"], remote_cfg["api_key"])

    try:
        current_ip = remote_client.get_external_ip(
            host_id=remote_cfg.get("host_id", ""),
            wan_key=remote_cfg.get("wan_key", "WAN"),
        )
    except RemoteApiError as exc:
        logger.error("could not fetch remote IP: %s", exc)
        return 2

    state = read_state(state_file)
    previous_ip = state.get("external_ip")

    logger.debug("current remote IP=%s previous=%s", current_ip, previous_ip)

    if current_ip == previous_ip and not args.force:
        logger.debug("no change, nothing to do")
        return 0

    logger.info(
        "remote IP %s (was %s) - syncing port forward rules",
        current_ip,
        previous_ip or "unset",
    )

    local_client = LocalControllerClient(
        local_cfg["base_url"],
        local_cfg["api_key"],
        local_cfg.get("site", "default"),
        verify_ssl=local_cfg.get("verify_ssl", True),
    )

    try:
        _changed, errors = sync_port_forward_rules(
            local_client, config["port_forward_rules"], current_ip, logger, args.dry_run
        )
    except LocalApiError as exc:
        logger.error("could not list existing port forward rules: %s", exc)
        return 3

    if errors:
        logger.error(
            "%d rule(s) failed to update; keeping previous IP in state so this is retried next run",
            len(errors),
        )
        return 3

    if not args.dry_run:
        write_state(state_file, {"external_ip": current_ip})

    return 0


if __name__ == "__main__":
    sys.exit(main())
