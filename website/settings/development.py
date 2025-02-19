from .base import *
from .security import *
from .database import *
from .static import *
from .logging import *

ALLOWED_HOSTS = ['*']

SECURE_HSTS_SECONDS = 0
SECURE_SSL_REDIRECT = False
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False