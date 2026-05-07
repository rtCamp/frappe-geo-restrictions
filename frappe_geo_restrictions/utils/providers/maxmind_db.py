import frappe
import geoip2.database
import geoip2.errors


def get_country_from_ip(ip_address, settings):
	# MaxMind GeoLite2 database provider
	db_path = getattr(settings, "geoip_db_path", None)
	if not db_path:
		frappe.log_error("MaxMind DB path missing in GeoRestriction Settings.")
		return None

	try:
		reader = geoip2.database.Reader(db_path)
		response = reader.country(ip_address)
		if response and response.country and response.country.iso_code:
			return response.country.iso_code.upper()
	except geoip2.errors.AddressNotFoundError:
		return None
	except Exception as e:
		frappe.log_error(f"MaxMind DB lookup failed for {ip_address}: {e}")
	return None
