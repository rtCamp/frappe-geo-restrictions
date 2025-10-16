import frappe
from frappe.utils.caching import redis_cache

from .providers.ipinfo import get_country_from_ip as ipinfo_get_country_from_ip
from .providers.maxmind import get_country_from_ip as maxmind_get_country_from_ip
from .providers.maxmind_db import get_country_from_ip as maxmind_db_get_country_from_ip


def get_ip_address():
	if frappe.request:
		headers = frappe.request.headers
		if "X-Forwarded-For" in headers:
			return headers["X-Forwarded-For"]
		elif "X-Real-IP" in headers:
			return headers["X-Real-IP"]
		elif "HTTP_CLIENT_IP" in frappe.request.environ:
			return frappe.request.environ["HTTP_CLIENT_IP"]
		elif "HTTP_X_FORWARDED_FOR" in frappe.request.environ:
			return frappe.request.environ["HTTP_X_FORWARDED_FOR"]
		elif "HTTP_X_FORWARDED" in frappe.request.environ:
			return frappe.request.environ["HTTP_X_FORWARDED"]
		else:
			return frappe.request.remote_addr
	return None


def get_country_from_ip(ip_address: str, user: str | None = None):
	"""
	Resolve country (ISO code) from an IP address.
	Allows pre-processing / override via hook: before_ip_fetch
	Each hook method is called with ip_address=<str>.
	If any hook returns a non-None value, that value is used directly.
	If all return None, fallback to GeoIP2 lookup.
	"""
	if not ip_address:
		return None

	# Hook override (first non-None wins)
	try:
		for method in frappe.get_hooks("before_ip_fetch") or []:
			try:
				result = frappe.call(method, ip_address=ip_address, user=user)
				if result is not None:
					return result
			except Exception:
				frappe.log_error(f"before_ip_fetch hook failed: {method}")
	except Exception:
		frappe.log_error("Failed to load before_ip_fetch hooks.")
	return _get_country_from_ip(ip_address)


@redis_cache(ttl=21600, user=False, shared=True)  # cache for 6 hours
def _get_country_from_ip(ip_address: str):
	# Fetch settings (cached)
	try:
		settings = frappe.get_cached_doc("GeoRestriction Settings")
	except Exception:
		frappe.log_error("Could not load GeoRestriction Settings for IP lookup.")
		return None

	provider = (getattr(settings, "ip_provider", "") or "").strip() or "IPInfo.io"

	if provider == "IPInfo.io":
		return ipinfo_get_country_from_ip(ip_address, settings)

	if provider == "MaxMind API":
		return maxmind_get_country_from_ip(ip_address, settings)

	if provider == "MaxMind DB":
		return maxmind_db_get_country_from_ip(ip_address, settings)

	frappe.log_error(f"Unknown IP provider configured: {provider}")
	return None
