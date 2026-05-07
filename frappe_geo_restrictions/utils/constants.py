from werkzeug.wrappers import Response


class ACCESS_MODES:
	NO_ACCESS = 0
	READ_ONLY = 1
	FULL_ACCESS = 2


class CustomNoAccess:
	def __init__(self, title, description, custom_template=None, status_code=403):
		self.title = title
		self.description = description
		self.custom_template = custom_template
		self.status_code = status_code

	def __int__(self):
		return ACCESS_MODES.NO_ACCESS


ACCESS_TIER_CACHE_PREFIX = "access_cache:"
IP_SETTINGS_CACHE_PREFIX = "ip_settings_cache:"

BYPASS_USERS_CACHE_PREFIX = "georestriction_user_roles_bypass::"
BYPASS_USERS_CACHE_TTL = 86400


__all__ = [
	"ACCESS_MODES",
	"ACCESS_TIER_CACHE_PREFIX",
	"BYPASS_USERS_CACHE_PREFIX",
	"BYPASS_USERS_CACHE_TTL",
	"IP_SETTINGS_CACHE_PREFIX",
	"CustomNoAccess",
	"Response",
]
