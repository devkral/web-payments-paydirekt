from __future__ import unicode_literals
import os

PROJECT_ROOT = os.path.normpath(
    os.path.join(os.path.dirname(__file__), 'payments'))
TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [os.path.join(PROJECT_ROOT, 'templates')]}]

SECRET_KEY = 'NOTREALLY'
PAYMENT_HOST = 'example.com'

INSTALLED_APPS = ['django.contrib.sites', 'web_payments.django']


PAYMENT_VARIANTS_API = {
    'paydirekt': ('web_payments_paydirekt.BankTransferProvider', {
        "api_key":'87dbc6cd-91d2-4574-bcb5-2aaaf924386d',
        "secret": '9Tth0qty_9zplTyY0d_QbHYvKM4iSngjoipWO6VxAao=',
        "endpoint": "https://api.sandbox.paydirekt.de",
        "overcapture": False
        }),
    }
