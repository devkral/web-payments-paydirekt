web-payments-paydirekt
======================

TODO: documentation

Usage:

add to PAYMENT_VARIANTS_API or varianttuple:

``` python
PAYMENT_VARIANTS_API = {
    ...
    'paydirekt': ('web_payments_paydirekt.PaydirektProvider', {
      "api_key": "<key>",
      "secret": "<secret>",
      "endpoint": "https://api.sandbox.paydirekt.de",
      "overcapture": False, # or True if you want to use the overcapture feature
      "default_carttype": "PHYSICAL"
      }, {}
    )
  }
```
