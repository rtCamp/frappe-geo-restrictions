import re

import frappe
from frappe import _
from frappe.utils.user import is_website_user
from werkzeug.exceptions import HTTPException

from frappe_ip_ban.utils.constants import (
	ACCESS_MODES,
	ACCESS_TIER_CACHE_PREFIX,
	BYPASS_USERS_CACHE_PREFIX,
	BYPASS_USERS_CACHE_TTL,
	IP_SETTINGS_CACHE_PREFIX,
)
from frappe_ip_ban.utils.ip import get_country_from_ip, get_ip_address


def get_ip_settings():
	if hasattr(frappe.local, "ip_ban_settings"):
		return frappe.local.ip_ban_settings
	settings = frappe.cache().get_value(IP_SETTINGS_CACHE_PREFIX + "global")
	if settings is None:
		settings = frappe.get_single("GeoRestriction Settings")
		frappe.cache().set_value(IP_SETTINGS_CACHE_PREFIX + "global", settings, expires_in_sec=3600)
	frappe.local.ip_ban_settings = settings
	return settings


def should_bypass_ip_restrictions(user: str) -> bool:
	"""
	Return True if the user should bypass IP restrictions.

	The final boolean decision is cached (per user) for BYPASS_USERS_CACHE_TTL seconds.
	Cache is invalidated via invalidate_bypass_users_cache().
	"""
	if not user:
		user = frappe.session.user if hasattr(frappe, "session") else "Guest"

	cache_key = f"{BYPASS_USERS_CACHE_PREFIX}{user}"
	cached = frappe.cache().get_value(cache_key)
	if cached is not None:
		return bool(cached)

	settings = get_ip_settings()

	# Order: any early "True" short-circuits
	if settings.bypass_admins and user == "Administrator":
		result = True
	elif settings.bypass_system_users and not is_website_user(user):
		result = True
	elif settings.bypass_guest_users and user == "Guest":
		result = True
	elif settings.bypass_role_based and settings.bypass_roles:
		bypass_roles = {r.role for r in settings.bypass_roles}
		user_roles = set(frappe.get_roles(user))
		result = bool(user_roles & bypass_roles)
	else:
		result = False

	frappe.cache().set_value(cache_key, int(result), expires_in_sec=BYPASS_USERS_CACHE_TTL)
	return result


def _normalize_access_tier(value) -> int:
	"""
	Convert DB / string value to ACCESS_MODES constant.
	Defaults to FULL_ACCESS on unknown input.
	"""
	if not value:
		return ACCESS_MODES.FULL_ACCESS
	if isinstance(value, int):
		if value in (ACCESS_MODES.NO_ACCESS, ACCESS_MODES.READ_ONLY, ACCESS_MODES.FULL_ACCESS):
			return value
		return ACCESS_MODES.FULL_ACCESS
	value_str = str(value).strip().lower()
	access_map = {
		"no access": ACCESS_MODES.NO_ACCESS,
		"read-only access": ACCESS_MODES.READ_ONLY,
		"full access": ACCESS_MODES.FULL_ACCESS,
	}
	return access_map.get(value_str, ACCESS_MODES.FULL_ACCESS)


def _most_restrictive(current: int, candidate: int) -> int:
	"""
	Return the most restrictive access mode.
	Restrictiveness order: NO_ACCESS > READ_ONLY > FULL_ACCESS
	"""
	order = [
		ACCESS_MODES.NO_ACCESS,
		ACCESS_MODES.READ_ONLY,
		ACCESS_MODES.FULL_ACCESS,
	]
	idx_current = order.index(current) if current in order else len(order)
	idx_candidate = order.index(candidate) if candidate in order else len(order)
	return order[idx_current] if idx_current < idx_candidate else order[idx_candidate]


def _apply_restrict_geoip_hooks(access_type: int, ip_address: str, country: str, user: str | None) -> int:
	"""
	Allow other apps to adjust (tighten or relax) the access_type via the
	'restrict_geoip' hook.

	Each hook method may return:
	  - None: no change
	  - A value (int/str) representing an ACCESS_MODES tier; it will be normalized.
	Hooks are applied sequentially; each may further restrict (or expand) access.
	If you want to ensure 'most restrictive wins', return a stricter mode than the current.
	Each hook must implement its own caching if needed.

	Example (in another app's hooks.py):
	    restrict_geoip = [
	        "my_app.geo_hooks.block_if_address_country_banned"
	    ]

	Example hook implementation:
	    def block_if_address_country_banned(access_type, ip_address, country, user, **kwargs):
	        if user and is_user_address_country_banned(user):
	            return ACCESS_MODES.NO_ACCESS
	        return None
	"""
	for method_path in frappe.get_hooks("restrict_geoip") or []:
		try:
			method = frappe.get_attr(method_path)
		except Exception:
			frappe.log_error(frappe.get_traceback(), "restrict_geoip hook import failure")
			continue
		try:
			result = method(
				access_type=access_type,
				ip_address=ip_address,
				country=country,  # lowercase country code resolved from IP
				user=user,
			)
			if result is None:
				continue
			normalized = _normalize_access_tier(result)
			# Choose the most restrictive between current and hook result
			access_type = _most_restrictive(access_type, normalized)
		except Exception:
			frappe.log_error(frappe.get_traceback(), "restrict_geoip hook execution failure")
	return access_type


def _get_country_access_type(ip_address: str, user=None) -> int:
	"""
	Return access type (one of ACCESS_MODES) for the given IP.
	Base determination: Country record's custom_access_tier (cached 1 day).
	Post-processing: apply 'restrict_geoip' hook so other apps can impose
	additional geo / user specific constraints.
	"""
	if not ip_address:
		return ACCESS_MODES.FULL_ACCESS

	if should_bypass_ip_restrictions(user):
		return ACCESS_MODES.FULL_ACCESS

	country_raw = get_country_from_ip(ip_address, user) or ""
	country = country_raw.lower()
	if not country:
		base_access = ACCESS_MODES.FULL_ACCESS
	else:
		cache_key = f"{ACCESS_TIER_CACHE_PREFIX}{country}"
		access_type = frappe.cache().get_value(cache_key)
		if access_type is None:
			raw = frappe.db.get_value("Country", {"code": country}, "custom_access_tier")
			access_type = _normalize_access_tier(raw)
			frappe.cache().set_value(cache_key, access_type, expires_in_sec=86400)  # 1 day
		base_access = access_type

	# Allow other apps to refine/restrict access
	final_access = _apply_restrict_geoip_hooks(base_access, ip_address, country, user)
	return final_access


class GeoRestrictedError(HTTPException):
	code = 403

	def __init__(self, description=None):
		if description is None:
			description = _("You do not have access to this site from your current location.")
		super().__init__(description=description)


def before_request():
	settings = get_ip_settings()
	if not settings.enabled:
		return

	user = getattr(frappe.session, "user", None)

	ip = get_ip_address()

	access_type = _get_country_access_type(ip, user)
	frappe.flags.access_type = access_type  # numeric ACCESS_MODES value

	if access_type == ACCESS_MODES.NO_ACCESS:
		raise GeoRestrictedError()

	if access_type == ACCESS_MODES.READ_ONLY and user and user != "Guest":
		frappe.flags.read_only = True


def has_permission(doc, ptype=None, user=None):
	"""
	Enforce access type (set in before_request) on all document operations,
	including those granted via sharing.
	"""
	settings = get_ip_settings()
	if not settings.enabled:
		return True

	if not getattr(frappe.local, "request", None):
		return True

	user = user or getattr(frappe.session, "user", None)

	if should_bypass_ip_restrictions(user):
		return True

	access_type = getattr(frappe.flags, "access_type", ACCESS_MODES.FULL_ACCESS)

	if access_type == ACCESS_MODES.NO_ACCESS:
		return False

	if access_type == ACCESS_MODES.READ_ONLY:
		if ptype is None:
			return True
		read_like = {"read", "print", "email", "export"}
		if ptype not in read_like:
			return False

	return True


def after_request(response):
	settings = get_ip_settings()
	if not settings.enabled or not settings.inject_readonly_script:
		return

	# Skip if no request context or if this is a Desk page (/app or /desk)
	req = getattr(frappe.local, "request", None)
	req_path = getattr(req, "path", "") if req else ""
	if req_path.startswith(("/app", "/desk")):
		return

	if getattr(frappe.flags, "access_type", ACCESS_MODES.FULL_ACCESS) != ACCESS_MODES.READ_ONLY:
		return

	content_type = response.headers.get("Content-Type", "")

	# Only process HTML responses
	if "text/html" in content_type and isinstance(response.response, list):
		try:
			# Handle bytes or str
			html_bytes = response.response[0]
			html_str = html_bytes.decode("utf-8") if isinstance(html_bytes, bytes) else html_bytes

			# Inject your script before the last </body> (case-insensitive)
			script_tag = '<script src="/assets/frappe_ip_ban/js/website.js"></script>'
			pattern = re.compile(r"</body>", re.IGNORECASE)
			matches = list(pattern.finditer(html_str))
			if matches:
				last = matches[-1]
				closing_tag = last.group(0)  # Preserve original case
				insertion_index = last.start()
				html_str = html_str[:insertion_index] + f"{script_tag}{closing_tag}" + html_str[last.end() :]
				response.set_data(html_str)
		except Exception as e:
			frappe.logger().error(f"Error injecting script tag: {e}")
