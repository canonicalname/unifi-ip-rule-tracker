# unifi_ip_rule_tracker

Watches a remote UniFi network's public IP (via the UniFi Site Manager API)
and keeps a local UniFi controller's port forward rules restricted to that
IP, so a remote site with a non-static address can reliably reach a host on
the local network without opening the port to the whole internet.

## How it works

1. Reads `config.yaml` for API keys and port forward rule templates.
2. Calls the remote Site Manager API and reads the current WAN IP from
   `reportedState.wans[].ipv4` in the response.
3. Compares it to the IP cached in `state.json`. If unchanged, exits
   immediately.
4. If changed, fetches the local controller's existing port forward rules
   and creates/updates each configured rule so its `src` field (source IP
   restriction) is set to `<remote_ip>`. Everything else about the rule
   (port, protocol, destination host) comes from the template in
   `config.yaml`.
5. Logs every check and change to `ip_rule_tracker.log` (rotated
   automatically) and updates `state.json` only once the local update
   succeeds, so a failed run gets retried on the next cron tick.

A lock file prevents two cron runs from overlapping if one takes longer
than the interval.

## Setup

```bash
cd /opt/unifi_ip_rule_tracker
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt

cp config.example.yaml config.yaml
chmod 600 config.yaml
# edit config.yaml: remote/local API keys, controller URL, port forward rules
```

Before trusting the cron job, verify both APIs manually:

```bash
# remote: should return {"data": [...]} with a reportedState.wans[] entry
curl -s -H "X-API-KEY: <remote_key>" https://api.ui.com/v1/hosts | head -c 500

# local: should return {"data": [...]} - adjust the site name if not "default"
curl -sk -H "X-API-KEY: <local_key>" \
  https://<controller-ip>/proxy/network/api/s/default/rest/portforward
```

If your controller's local API uses a different path (this varies by
firmware/console generation), edit `local.base_url` in `config.yaml` or the
URL building in `LocalControllerClient` in `ip_rule_tracker.py`.

Then do a dry run:

```bash
./.venv/bin/python ip_rule_tracker.py --config config.yaml --dry-run --verbose --force
```

`--force` re-evaluates the rules even though there's no cached state yet;
`--dry-run` logs what would change without calling the local API.

## Cron

Run on whatever interval suits how quickly your remote IP tends to change
(e.g. hourly), using the venv's interpreter directly (no activation needed):

```cron
0 * * * * /opt/unifi_ip_rule_tracker/.venv/bin/python /opt/unifi_ip_rule_tracker/ip_rule_tracker.py --config /opt/unifi_ip_rule_tracker/config.yaml >> /opt/unifi_ip_rule_tracker/cron_errors.log 2>&1
```

Routine activity is already logged to `ip_rule_tracker.log`; the
`cron_errors.log` redirect above only catches things like a missing venv or
an uncaught exception before logging is set up.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | OK - no change, or change applied successfully |
| 1 | Config error (missing/invalid `config.yaml`) |
| 2 | Remote API error (couldn't fetch external IP) |
| 3 | Local API error (one or more rules failed to update - state not advanced, will retry) |
| 4 | Another run is already in progress |
