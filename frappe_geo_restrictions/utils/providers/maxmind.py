import frappe
import geoip2.errors
import geoip2.webservice


def get_country_from_ip(ip_address, settings) -> str | None:
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
