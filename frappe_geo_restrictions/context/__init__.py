import frappe

from frappe_geo_restrictions.utils.constants import ACCESS_MODES


def boot_session(bootinfo):
	bootinfo.user_access_tier = getattr(frappe.flags, "access_type", ACCESS_MODES.FULL_ACCESS)
