# from .base import *
# import os

# LOGGING = {
#     'version': 1,
#     'disable_existing_loggers': False,
#     'formatters': {
#         'standard': {
#             'format': '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s',
#             'datefmt': '%Y-%m-%d %H:%M:%S',
#         },
#         'verbose': {
#             'format': '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(module)s: %(message)s',
#             'datefmt': '%Y-%m-%d %H:%M:%S',
#         },
#     },
#     'handlers': {
#         'file': {
#             'level': 'DEBUG',
#             'class': 'logging.handlers.RotatingFileHandler',  # Use rotating file handler
#             'filename': os.path.join(BASE_DIR, 'logs', 'django.log'),
#             'maxBytes': 1024 * 1024 * 5,  # 5 MB
#             'backupCount': 5,  # Keep last 5 log files
#             'formatter': 'standard',
#     },
#         'console': {
#             'level': 'DEBUG',
#             'class': 'logging.StreamHandler',
#             'formatter': 'verbose',  # Use the 'verbose' formatter for console handler
#         },
#     },
#     'loggers': {
#         'django': {
#             'handlers': ['file', 'console'],  # Use both file and console handlers
#             'level': 'DEBUG' if DEBUG else 'WARNING',
#             'propagate': True,
#         },
#         'django.request': {
#             'handlers': ['file', 'console'],
#             'level': 'ERROR',  # Log only errors for the request logger
#             'propagate': False,
#         },
#         'django.security': {
#             'handlers': ['file', 'console'],
#             'level': 'WARNING',  # Log security warnings
#             'propagate': False,
#         },
#     },
# }
