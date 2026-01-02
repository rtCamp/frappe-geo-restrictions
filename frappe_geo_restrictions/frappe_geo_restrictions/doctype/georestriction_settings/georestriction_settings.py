# Copyright (c) 2025, rtCamp and contributors
# For license information, please see license.txt

# import frappe
from frappe.model.document import Document


class GeoRestrictionSettings(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.core.doctype.user_role.user_role import UserRole
		from frappe.types import DF

		bypass_admins: DF.Check
		bypass_guest_users: DF.Check
		bypass_role_based: DF.Check
		bypass_roles: DF.TableMultiSelect[UserRole]
		bypass_system_users: DF.Check
		enabled: DF.Check
		geoip_account_id: DF.Data | None
		geoip_db_path: DF.Data | None
		geoip_host: DF.Data | None
		geoip_license_key: DF.Password | None
		inject_readonly_script: DF.Check
		ip_provider: DF.Literal["IPInfo.io", "MaxMind API", "MaxMind DB"]
		ipinfo_token: DF.Password | None
	# end: auto-generated types

	pass
