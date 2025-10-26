import ipaddress

import frappe
from frappe.utils.caching import redis_cache

from .providers.ipinfo import get_country_from_ip as ipinfo_get_country_from_ip
from .providers.maxmind import get_country_from_ip as maxmind_get_country_from_ip
from .providers.maxmind_db import get_country_from_ip as maxmind_db_get_country_from_ip


def get_ip_address():
	"""
	Retrieve the real IP address of the client making the request,
	considering various proxy headers (Cloudflare, Nginx, etc.).
	"""
	if not frappe.request:
		return None

	headers = frappe.request.headers
	environ = frappe.request.environ

	# Order of trust: Cloudflare > X-Forwarded-For > X-Real-IP > fallback
	ip_sources = [
		headers.get("CF-Connecting-IP"),  # Cloudflare
		headers.get("X-Forwarded-For"),  # Could be a list of IPs
		headers.get("X-Real-IP"),
		environ.get("HTTP_CLIENT_IP"),
		environ.get("HTTP_X_FORWARDED_FOR"),
		environ.get("HTTP_X_FORWARDED"),
		frappe.request.remote_addr,
	]

	for ip in ip_sources:
		if not ip:
			continue

		# Some headers (e.g. X-Forwarded-For) may contain multiple IPs
		# like: "198.51.100.1, 10.0.0.1"
		ip = ip.split(",")[0].strip()

		# Optional: validate it's a public IP (not internal Docker/localhost)
		try:
			parsed_ip = ipaddress.ip_address(ip)
			if not parsed_ip.is_private and not parsed_ip.is_loopback:
				return ip  # Return first public, non-local IP
		except ValueError:
			continue  # Skip invalid IPs

	return None  # If nothing valid found


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
