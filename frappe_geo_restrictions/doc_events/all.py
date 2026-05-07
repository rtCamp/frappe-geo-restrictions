import frappe

from frappe_geo_restrictions.utils import should_bypass_ip_restrictions
from frappe_geo_restrictions.utils.constants import ACCESS_MODES


def before_validate(doc, method=None):
	"""
	Prevent saving documents if access type is NO_ACCESS or READ_ONLY.
	"""
	if not getattr(frappe.local, "request", None):
		return

	ignore_permissions = getattr(doc.flags, "ignore_permissions", False)
	if ignore_permissions:
		return

	user = getattr(frappe.session, "user", None)
	if not user or should_bypass_ip_restrictions(user):
		return

	access_type = getattr(frappe.flags, "access_type", ACCESS_MODES.FULL_ACCESS)

	if access_type == ACCESS_MODES.NO_ACCESS:
		frappe.throw(frappe._("You do not have permission to perform this action."), frappe.PermissionError)

	if access_type == ACCESS_MODES.READ_ONLY:
		frappe.throw(frappe._("You have read-only access and cannot modify data."), frappe.PermissionError)
