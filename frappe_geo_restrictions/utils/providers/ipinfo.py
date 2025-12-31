import frappe
import requests


def get_country_from_ip(ip_address, settings) -> str | None:
	try:
		token = settings.get_password("ipinfo_token") if settings.get("ipinfo_token") else None

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
