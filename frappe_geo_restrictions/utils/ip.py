import frappe
import geoip2.webservice
import requests
from frappe.utils.caching import redis_cache


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


@redis_cache(ttl=7 * 24 * 60 * 60, user=False, shared=True)  # cache for 7 days
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

	# Fetch settings (cached)
	try:
		settings = frappe.get_cached_doc("GeoRestriction Settings")
	except Exception:
		frappe.log_error("Could not load GeoRestriction Settings for IP lookup.")
		return None

	provider = (getattr(settings, "ip_provider", "") or "").strip() or "IPInfo.io"

	if provider == "IPInfo.io":
		# IPInfo.io provider
		try:
			try:
				token = settings.get_password("ipinfo_token")
			except Exception:
				token = getattr(settings, "ipinfo_token", None)

			base_url = f"https://ipinfo.io/{ip_address}"
			if token:
				url = f"{base_url}?token={token}"
			else:
				url = base_url

			resp = requests.get(url, timeout=4)
			if resp.status_code == 200:
				data = {}
				try:
					data = resp.json()
				except Exception:
					frappe.log_error(f"IPInfo.io non-JSON response for {ip_address}")
					return None
				country = (data.get("country") or "").strip().upper()
				if country:
					return country
			elif resp.status_code == 404:
				return None
			else:
				frappe.log_error(f"IPInfo.io HTTP {resp.status_code} for {ip_address}")
		except Exception as e:
			frappe.log_error(f"IPInfo.io lookup failed for {ip_address}: {e}")
		return None

	if provider == "MaxMind":
		# MaxMind GeoIP2 Web Service provider
		geoip_host = getattr(settings, "geoip_host", "geolite.info")
		account_id = getattr(settings, "geoip_account_id", None)
		try:
			license_key = settings.get_password("geoip_license_key")
		except Exception:
			license_key = getattr(settings, "geoip_license_key", None)

		if not account_id or not license_key:
			frappe.log_error("MaxMind credentials missing in GeoRestriction Settings.")
			return None

		try:
			client = geoip2.webservice.Client(account_id, license_key, host=geoip_host)
			response = client.country(ip_address)
			if response and response.country and response.country.iso_code:
				return response.country.iso_code.upper()
		except geoip2.errors.AddressNotFoundError:
			return None
		except Exception as e:
			frappe.log_error(f"MaxMind lookup failed for {ip_address}: {e}")
		return None

	frappe.log_error(f"Unknown IP provider configured: {provider}")
	return None
