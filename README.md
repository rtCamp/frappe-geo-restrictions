# Frappe Geo Restrictions

Control user access (Full, Read-Only, or No Access) based on the country detected from their IP. Supports role-based bypass and extension hooks.

## TL;DR

- Set an Access Tier on each Country: Full / Read-Only / No Access
- Each request is classified early; the most restrictive rule wins
- Optional bypass by role or user type
- Auto IP → Country via IPInfo.io or MaxMind API or MaxMind DB
- Read-only enforced on server and (optionally) in the UI
- Hooks let you override country detection or adjust decisions
- Layered caching with safe invalidation

## Installation

```bash
cd /path/to/bench
bench get-app https://github.com/rtCamp/frappe-geo-restrictions --branch main
bench install-app frappe_geo_restrictions
bench migrate
```

## Quick Start

1. Install the app (see above).
2. Go to: GeoRestriction Settings
   - Enable it.
   - Pick IP provider & add credentials if needed.
   - (Optional) Turn on read-only script injection if you're using website pages.
3. Open a Country record; set "Access Tier" (default: Full Access).
4. Test:
   - From a Read-Only country: writes blocked; UI disabled (if script on).
   - From a No Access country: request returns 403 early.
5. (Optional) Set bypass:
   - Toggle admin/system/guest bypass
   - Add roles under Bypass Roles & enable role-based bypass
6. (Optional) Extend:
   - Add hooks (`before_ip_fetch`, `restrict_geoip`) in your app.

## Core Feature Summary

| Feature | Purpose |
|---------|---------|
| Country Access Tier | Per-country restriction level |
| Read-Only Mode | Blocks changes (server + optional UI script) |
| No Access | Fast 403 |
| Bypass Rules | Admin/System/Guest/Role-based short-circuit |
| Hooks | Pre-IP override & post-decision tweak |
| Caching | Settings, tiers, bypass, IP → country |
| Front-End Banner | Visual notice + enforced disabling |
| Boot Info Flag | `bootinfo.user_access_tier` for client logic |

## Troubleshooting (Common)

| Symptom | Likely Cause | Action |
|---------|--------------|--------|
| Always Full Access | Bypass matched or disabled | Check settings & roles |
| Not Read-Only UI | Script not enabled | Turn on `inject_readonly_script` |
| Unknown Country | Provider setup issue | Check credentials & logs |
| Stale Bypass | Cached decision | Role/user change should clear; else clear cache |
| Unexpected 403 | Country = No Access or hook override | Inspect Country + hooks |

Manual cache clearing (bench console):
```python
import frappe
from frappe_geo_restrictions.utils.cache_invalidation import (
    invalidate_ip_settings_cache,
    invalidate_bypass_users_cache,
)
invalidate_ip_settings_cache(None)
invalidate_bypass_users_cache()
```

## When To Use Read-Only vs No Access

| Mode | Ideal For |
|------|-----------|
| Read-Only | Compliance, maintenance, phased rollout |
| No Access | Hard geo block / licensing |

---

## Advanced Reference (Expand Sections Below)

<details>
<summary><strong>Access Modes & Resolution Flow</strong></summary>

### Access Modes (Constants)
```
0 = NO_ACCESS
1 = READ_ONLY
2 = FULL_ACCESS
```
Order of restrictiveness: NO_ACCESS > READ_ONLY > FULL_ACCESS.

### Resolution Flow
1. before_request:
   - Load cached settings
   - Get user + IP
   - (Optional) Run `before_ip_fetch` hook
   - Provider lookup → country (ISO)
   - Read Country `custom_access_tier`
   - Run `restrict_geoip` hooks (can change tier)
   - Set `frappe.flags.access_type`
   - If READ_ONLY (non-Guest): set `frappe.flags.read_only`
   - If NO_ACCESS: raise 403
2. Permission funnel:
   - Global `has_permission` hook
   - `before_validate` doc event (blocks website writes)
   - Optional UI script (website pages)
3. after_request:
   - Inject read-only JS when needed (HTML & non-Desk)

</details>

<details>
<summary><strong>Country & Settings Configuration</strong></summary>

### Country Custom Field
Fieldname: `custom_access_tier` (Select: Full Access / Read-Only Access / No Access; required; default Full Access)

### GeoRestriction Settings (Doctype)
| Field | Purpose |
|-------|---------|
| enabled | Master toggle |
| ip_provider | IPInfo.io / MaxMind API |
| ipinfo_token | IPInfo token |
| geoip_account_id | MaxMind account ID |
| geoip_license_key | MaxMind license (Password) |
| geoip_host | Optional host override |
| geoip_db_path | Optional local DB path |
| inject_readonly_script | Enable UI enforcement |
| bypass_admins | Bypass Administrator |
| bypass_system_users | Bypass System Users |
| bypass_guest_users | Bypass Guest |
| bypass_role_based | Enable role bypass |
| bypass_roles (table) | Role list |

### Bypass Short-Circuit Order
1. Administrator (if enabled)
2. System User (if enabled)
3. Guest (if enabled)
4. Role match (if enabled)
5. Else: use tier

Cached per-user (86400s).

</details>

<details>
<summary><strong>Caching Model</strong></summary>

| Cache | Key | TTL | Invalidated By |
|-------|-----|-----|----------------|
| Settings | ip_settings_cache:global | 3600s | Settings change |
| Country Tier | access_cache:{code} | 86400s | Country on_change |
| Bypass Decision | georestriction_user_roles_bypass::{user} | 86400s | User/Role/Settings change |
| IP → Country | `@redis_cache` decorator | 7 days | Expiry |

Invalidation helpers: `utils/cache_invalidation.py`

</details>

<details>
<summary><strong>Front-End Read-Only Script</strong></summary>

Injected when:
- Tier = READ_ONLY
- Not `/app` or `/desk`
- HTML response
- Setting enabled

Behavior:
- `<html>` gets `access-tier-1`
- Banner added (`data-testid="readonly-banner"`)
- Disables: `input, textarea, select, button`
- MutationObserver re-applies
- Prevents easy re-enable

Override Helpers:

Allow:
```html
<div class="allow-in-readonly"><input /></div>
```
Force disable:
```html
<div class="disallow-in-readonly"><button>Blocked</button></div>
```
Manual reapply:
```js
window.__applyAccessTierBoundary && window.__applyAccessTierBoundary();
```

</details>

<details>
<summary><strong>Server Flags & Boot Info</strong></summary>

- `frappe.flags.access_type`: numeric constant always set
- `frappe.flags.read_only`: only when READ_ONLY & non-Guest
- `bootinfo.user_access_tier`: for client logic

</details>

<details>
<summary><strong>Hooks</strong></summary>

### 1. before_ip_fetch
Early override:
```python
def my_before_ip_fetch(ip_address: str, user: str | None = None):
    return None  # or ISO country
```
`before_ip_fetch = ["my_app.geo.hooks.my_before_ip_fetch"]`

### 2. restrict_geoip
Refine enforcement:
```python
from frappe_geo_restrictions.utils.constants import ACCESS_MODES

def force_block_high_risk(access_type, ip_address, country, user, **kwargs):
    if country in {"kp", "xx"}:
        return ACCESS_MODES.NO_ACCESS
    return None
```
`restrict_geoip = ["my_app.geo.hooks.force_block_high_risk"]`

Return only when changing the decision.

</details>

<details>
<summary><strong>Programmatic API</strong></summary>

| Function | Path | Purpose |
|----------|------|---------|
| get_ip_address | utils/ip.py | Get request IP |
| get_country_from_ip | utils/ip.py | Cached IP → country |
| should_bypass_ip_restrictions | utils/__init__.py | Bypass check |
| get_ip_settings | utils/__init__.py | Cached settings |
| has_permission | utils/__init__.py | Global permission hook |
| GeoRestrictedError | utils/__init__.py | 403 error class |

</details>

<details>
<summary><strong>Enforcement & Doc Events</strong></summary>

- `before_validate`: blocks writes (Website Users) when READ_ONLY / NO_ACCESS unless `doc.flags.ignore_permissions`
- Global permission hook aligns Desk/API
- Server always authoritative; UI script is extra

</details>

<details>
<summary><strong>Extension Examples</strong></summary>

Whitelist partner IP block:
```python
def partner_override(ip_address, user=None):
    if ip_address.startswith("203.0.113."):
        return "Full Access"
    return None
before_ip_fetch = ["my_app.geo.partner_override"]
```

Maintenance window read-only:
```python
from datetime import datetime
from frappe_geo_restrictions.utils.constants import ACCESS_MODES

def maintenance_lock(access_type, **ctx):
    if 1 <= datetime.utcnow().hour <= 2:
        return ACCESS_MODES.READ_ONLY
    return None
restrict_geoip = ["my_app.geo.maintenance_lock"]
```

Disable globally (dev only):
```python
frappe.get_single("GeoRestriction Settings").db_set("enabled", 0)
```

</details>

<details>
<summary><strong>Development & Contribution</strong></summary>

Pre-commit tooling (ruff, eslint, prettier, pyupgrade):
```bash
cd apps/frappe_geo_restrictions
pre-commit install
```

Reverse proxy: ensure correct `X-Forwarded-For`.

Security: server checks are primary; UI script is helper.

</details>

---

## License

AGPL-3.0

## Attribution

Maintained by rtCamp.
