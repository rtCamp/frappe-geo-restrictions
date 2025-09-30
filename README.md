# Frappe Geo Restrictions

Restrict user access (Full, Read-Only, or No Access) dynamically based on a user's IP-derived country, with role-based bypasses and extensibility hooks.

## TL;DR

- Assign each Country an Access Tier: Full / Read-Only / No Access
- Requests are classified early; most restrictive rule wins
- Optional role / user-type based bypass
- Automatic IP → Country via IPInfo.io or MaxMind
- Read-only mode enforced both server-side and (optionally) in the UI
- Hooks let you override country resolution & refine access
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
2. Open: GeoRestriction Settings
   - Check "Enabled"
   - Pick IP provider & add credentials if required.
   - (Optional) Enable read-only script injection.
3. Open a Country record; set "Access Tier" (default is Full Access).
4. Test:
   - From an IP in a "Read-Only" country: writes should be blocked, UI disabled (if script enabled).
   - From a "No Access" country: request should 403 early.
5. Configure bypass (optional):
   - Toggle admin/system/guest bypass
   - Add roles under Bypass Roles & enable role-based bypass
6. Extend (optional):
   - Add hook entries (`before_ip_fetch`, `restrict_geoip`) in your app.

## Core Feature Summary

| Feature | Purpose |
|---------|---------|
| Country Access Tier | Per-country restriction level |
| Read-Only Mode | Locks mutations (server + optional UI script) |
| No Access | Fast 403 |
| Bypass Rules | Admin/System/Guest/Role-based short-circuit |
| Hooks | Pre-IP override & post-decision refinement |
| Caching | Settings, country tiers, bypass, IP → country |
| Front-End Banner | Visual indicator + enforced disabling |
| Boot Info Flag | `bootinfo.user_access_tier` for client logic |

## Troubleshooting (Common)

| Symptom | Likely Cause | Action |
|---------|--------------|--------|
| Always Full Access | Bypass matched or disabled | Review settings & roles |
| Not Read-Only UI | Script injection disabled | Enable `inject_readonly_script` |
| Unknown Country | Provider misconfig / network issue | Verify credentials & logs |
| Stale Bypass | Cached decision | Role/user change triggers invalidation; else clear cache |
| Unexpected 403 | Country = No Access or hook override | Inspect Country + hook chain |

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
| Read-Only | Compliance, maintenance, phased rollouts |
| No Access | Strict geo blocking / licensing boundaries |

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
Restrictiveness order: NO_ACCESS > READ_ONLY > FULL_ACCESS.

### Resolution Flow
1. before_request:
   - Load cached settings
   - Resolve user + IP
   - Optional: `before_ip_fetch` hook override
   - Provider lookup → country (ISO)
   - Fetch Country `custom_access_tier`
   - Apply `restrict_geoip` hooks (can modify tier)
   - Assign: `frappe.flags.access_type`
   - If READ_ONLY (non-Guest): set `frappe.flags.read_only`
   - If NO_ACCESS: raise 403 early
2. Permission funnel:
   - Global `has_permission` hook
   - `before_validate` doc event (website writes blocked)
   - Optional UI script (website pages)
3. after_request:
   - Inject read-only JS when applicable (HTML & non-Desk)

</details>

<details>
<summary><strong>Country & Settings Configuration</strong></summary>

### Country Custom Field
Fieldname: `custom_access_tier` (Select: Full Access / Read-Only Access / No Access; required; default Full Access)

### GeoRestriction Settings (Doctype)
| Field | Purpose |
|-------|---------|
| enabled | Master toggle |
| ip_provider | IPInfo.io / MaxMind |
| ipinfo_token | IPInfo token |
| geoip_account_id | MaxMind account ID |
| geoip_license_key | MaxMind license (Password) |
| geoip_host | Optional host override |
| inject_readonly_script | Enable UI enforcement |
| bypass_admins | Bypass for Administrator |
| bypass_system_users | Bypass for system (Desk) users |
| bypass_guest_users | Bypass for Guest |
| bypass_role_based | Enable role logic |
| bypass_roles (table) | Role list for role bypass |

### Bypass Short-Circuit Order
1. Administrator (if enabled)
2. System User (if enabled)
3. Guest (if enabled)
4. Role intersection (if enabled)
5. Else: proceed with tier

Cached per-user (86400s).

</details>

<details>
<summary><strong>Caching Model</strong></summary>

| Cache | Key | TTL | Invalidated By |
|-------|-----|-----|----------------|
| Settings | ip_settings_cache:global | 3600s | Settings change |
| Country Tier | access_cache:{code} | 86400s | Country on_change |
| Bypass Decision | georestriction_user_roles_bypass::{user} | 86400s | User/Role/Settings change |
| IP → Country | Provider decorator | 7 days | Natural expiry |

Invalidation helpers: `utils/cache_invalidation.py`

</details>

<details>
<summary><strong>Front-End Read-Only Script</strong></summary>

Injected when:
- Access tier = READ_ONLY
- Not `/app` or `/desk`
- HTML response
- Setting enabled

Behavior:
- `<html>` gets `access-tier-1`
- Banner inserted (`data-testid="readonly-banner"`)
- Disables: `input, textarea, select, button`
- MutationObserver re-applies
- Attribute tampering resisted

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
- `bootinfo.user_access_tier`: available to client scripts

</details>

<details>
<summary><strong>Hooks</strong></summary>

### 1. before_ip_fetch
Early override:
```python
def my_before_ip_fetch(ip_address: str, user: str | None = None):
    return None  # or ISO country
```
`before_ip_fetch = ["my_app.geo.hooks.override_private_ranges"]`

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

Return only when changing decision.

</details>

<details>
<summary><strong>Programmatic API</strong></summary>

| Function | Path | Purpose |
|----------|------|---------|
| get_ip_address | utils/ip.py | Extract request IP |
| get_country_from_ip | utils/ip.py | Cached IP → country |
| should_bypass_ip_restrictions | utils/__init__.py | Bypass evaluation |
| get_ip_settings | utils/__init__.py | Cached settings |
| has_permission | utils/__init__.py | Global permission hook |
| GeoRestrictedError | utils/__init__.py | 403 exception class |

</details>

<details>
<summary><strong>Enforcement & Doc Events</strong></summary>

- `before_validate`: blocks write attempts (Website Users) when READ_ONLY / NO_ACCESS unless `doc.flags.ignore_permissions`
- Global permission hook ensures Desk/API alignment
- Server-side always authoritative; UI script is additive

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

Reverse proxy: ensure correct `X-Forwarded-For` for accurate IP.

Security: rely on server checks; UI script is supplemental.

</details>

---

## License

AGPL-3.0

## Attribution

Maintained by rtCamp.
