import frappe

from frappe_geo_restrictions.utils.constants import (
	ACCESS_TIER_CACHE_PREFIX,
	BYPASS_USERS_CACHE_PREFIX,
	IP_SETTINGS_CACHE_PREFIX,
)
from frappe_geo_restrictions.utils.ip import _get_country_from_ip

# TODO: Add test cases. Reference: https://github.com/rtCamp/frappe-geo-restrictions/pull/2#discussion_r2405551148


def invalidate_ip_settings_cache(doc, method=None):
	cache = frappe.cache()
	cache.delete_key(IP_SETTINGS_CACHE_PREFIX + "global")
	if hasattr(frappe.local, "georestriction_settings"):
		delattr(frappe.local, "georestriction_settings")
	invalidate_bypass_users_cache()
	_get_country_from_ip.clear_cache()


def invalidate_bypass_users_cache(user: str | None = None):
	"""
	Invalidate cached should_bypass_ip_restrictions() results.

	If user is provided, only that user's cached decision is cleared.
	If user is None, all cached decisions are cleared.

	Call this when:
	  - User roles change (User save / Role update) -> pass specific user (or None if uncertain)
	  - GeoRestriction Settings change (especially bypass_* fields) -> pass None
	"""
	cache = frappe.cache()
	if user:
		cache.delete_key(f"{BYPASS_USERS_CACHE_PREFIX}{user}")
		return
	cache.delete_keys(BYPASS_USERS_CACHE_PREFIX)


def clear_countries_cache(doc, method=None):
	"""
	Clear cached country access tiers when a Country document is updated.
	"""
	if doc.get("code"):
		country_cache_key = f"{ACCESS_TIER_CACHE_PREFIX}{doc.code.lower()}"
		frappe.cache().delete_key(country_cache_key)


def on_user_and_role_change(doc, method):
	invalidate_bypass_users_cache(doc.name)
