""" paydirekt payment provider """

import uuid

from email.utils import format_datetime
from decimal import Decimal
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import time
import datetime
import hmac
# for hmac and hashed email
import hashlib
import simplejson as json
import logging

import requests
from requests.exceptions import Timeout

from web_payments import PaymentError, RedirectNeeded, PaymentStatus
from web_payments.logic import BasicProvider
from web_payments.utils import split_streetnr

logger = logging.getLogger(__name__)

__all__ = ["PaydirektProvider"]


CENTS = Decimal("0.01")


# Capture: if False ORDER is used
class PaydirektProvider(BasicProvider):
    '''
    paydirekt payment provider

    api_key:
        seller key, assigned by paydirekt
    secret:
        seller secret key (=encoded in base64)
    endpoint:
        which endpoint to use
    '''

    path_token = "{}/api/merchantintegration/v1/token/obtain"
    path_checkout = "{}/api/checkout/v1/checkouts"
    path_capture = "{}/api/checkout/v1/checkouts/{}/captures"
    path_close = "{}/api/checkout/v1/checkouts/{}/close"
    path_refund = "{}/api/checkout/v1/checkouts/{}/refunds"

    translate_status = {
        "APPROVED": PaymentStatus.CONFIRMED,
        "OPEN": PaymentStatus.PREAUTH,
        "PENDING": PaymentStatus.WAITING,
        "REJECTED": PaymentStatus.REJECTED,
        "CANCELED": PaymentStatus.ERROR,
        "CLOSED": PaymentStatus.CONFIRMED,
        "EXPIRED": PaymentStatus.ERROR,
    }
    header_default = {
        "Content-Type": "application/hal+json;charset=utf-8",
    }

    def __init__(self, api_key, secret, endpoint="https://api.sandbox.paydirekt.de",
                 overcapture=False, default_carttype="PHYSICAL",
                 timeout=20, **kwargs):
        self.secret_b64 = secret.encode('utf-8')
        self.api_key = api_key
        self.timeout = timeout
        self.endpoint = endpoint
        self.overcapture = overcapture
        self.default_carttype = default_carttype
        super(PaydirektProvider, self).__init__(**kwargs)

    def send_request(self, url, data=None, headers=None, add_token=True):
        if add_token:
            headers["Authorization"] = "Bearer %s" % self.token
        try:
            response = requests.post(url, data, headers=headers, timeout=self.timeout)
        except Timeout:
            raise PaymentError("Timeout")
        try:
            response_json = json.loads(response.text, use_decimal=True)
        except Exception:
            response_json = None

        if response.status_code not in [200, 201]:
            if response_json:
                if add_token:
                    isexpired = False
                    try:
                        for i in response_json["messages"]:
                            if i["code"] == "ACCESS_TOKEN_EXPIRED":
                                isexpired = True
                    except Exception:
                        pass
                    if isexpired:
                        return self.send_request(url, data, headers, add_token)
                try:
                    errorcode = response_json["messages"][0]["code"] if "messages" in response_json and len(response_json["messages"]) > 0 else None
                    raise PaymentError("{}\n--------------------\n{}".format(response.status_code, response_json), code=errorcode)
                except KeyError:
                    raise PaymentError(str(response.status_code))
            else:
                raise PaymentError(str(response.status_code))
        return response_json

    def get_auth_token(self, date_now):
        """ Retrieves oauth Token """
        token_uuid = str(uuid.uuid4()).encode("utf-8")
        nonce = urlsafe_b64encode(os.urandom(48))
        bytessign = token_uuid+b":"+date_now.strftime("%Y%m%d%H%M%S").encode('utf-8')+b":"+self.api_key.encode('utf-8')+b":"+nonce
        h_temp = hmac.new(urlsafe_b64decode(self.secret_b64), msg=bytessign, digestmod=hashlib.sha256)

        headers = PaydirektProvider.header_default.copy()
        headers["X-Auth-Key"] = self.api_key
        headers["X-Request-ID"] = token_uuid

        headers["X-Auth-Code"] = str(urlsafe_b64encode(h_temp.digest()), 'ascii')
        headers["Date"] = format_datetime(date_now, usegmt=True)
        body = {
            "grantType" : "api_key",
            "randomNonce" : str(nonce, "ascii")
        }
        token_raw = self.send_request(self.path_token.format(self.endpoint), data=json.dumps(body, use_decimal=True), headers=headers, add_token=False)
        # recovery from token expired time expensive and untested
        return token_raw["access_token"], date_now+datetime.timedelta(seconds=token_raw["expires_in"]-5)

    def _prepare_items(self, payment):
        items = []
        for newitem in payment.get_purchased_items():
            items.append({
                "name": newitem.name,
                # limit to 2 decimal_places even 4 decimal_places should be possible
                "price": newitem.price.quantize(CENTS),
                "quantity": int(newitem.quantity)
            })
        return items

    def _retrieve_amount(self, url):
        try:
            ret = requests.get(url, timeout=self.timeout)
        except Timeout:
            logger.error("paydirekt had timeout")
            return None
        try:
            results = json.loads(ret.text, use_decimal=True)
        except (ValueError, TypeError):
            logger.error("paydirekt returned unparseable object")
            return None
        return results.get("amount", None)

    def get_form(self, payment, data=None):
        if not payment.id:
            payment.save()
        headers = PaydirektProvider.header_default.copy()
        extras = payment.get_payment_extra()
        shipping = payment.get_shipping_address()
        email_hash = None
        if "email" in shipping:
            email_hash = str(urlsafe_b64encode(hashlib.sha256(shipping["email"].encode("utf-8")).digest()), 'ascii')
        total = payment.total.quantize(CENTS)
        delivery = extras["delivery"].quantize(CENTS)
        body = {
            "type": "ORDER" if not self._capture else "DIRECT_SALE",
            "totalAmount": total,
            "shippingAmount": delivery,
            "orderAmount": total - delivery,
            "currency": payment.currency,
            "refundLimit": 100,
            "shoppingCartType": extras.get("type", self.default_carttype),
            # payment id can repeat if different shop systems are used
            "merchantOrderReferenceNumber": "%s:%s" % (hex(int(time.time()))[2:], payment.id),
            "redirectUrlAfterSuccess": payment.get_success_url(),
            "redirectUrlAfterCancellation": payment.get_failure_url(),
            "redirectUrlAfterRejection": payment.get_failure_url(),
            "redirectUrlAfterAgeVerificationFailure": payment.get_failure_url(),
            "callbackUrlStatusUpdates": payment.get_process_url(),
            # email sent anyway (shipping)
            "sha256hashedEmailAddress": email_hash,
            "minimumAge": extras.get("minimumage", None)
        }
        if body["type"] == "DIRECT_SALE" and "message" in extras:
            body["note"] = extras["message"][:37]
        if self.overcapture and body["type"] in ["ORDER", "ORDER_SECURED"]:
            body["overcapture"] = True

        street, streetnr = split_streetnr(shipping["address_1"], "0")

        shipping = {
            "addresseeGivenName": shipping["first_name"],
            "addresseeLastName": shipping["last_name"],
            "company": shipping.get("company", None),
            "additionalAddressInformation": shipping["address_2"],
            "street": street,
            "streetNr": streetnr,
            "zip": shipping["postcode"],
            "city": shipping["city"],
            "countryCode": shipping["country_code"],
            "state": shipping["country_area"],
            "emailAddress": shipping.get("email", None)
        }
        # strip Nones
        shipping = {k: v for k, v in shipping.items() if v}
        body = {k: v for k, v in body.items() if v}

        body["shippingAddress"] = shipping

        items = self._prepare_items(payment)
        if len(items) > 0:
            body["items"] = items

        json_response = self.send_request(self.path_checkout.format(self.endpoint), data=json.dumps(body, use_decimal=True), headers=headers)

        payment.transaction_id = json_response["checkoutId"]
        # payment.attrs = json_response["_links"]
        payment.save()
        raise RedirectNeeded(json_response["_links"]["approve"]["href"])

    def process_data(self, payment, request):
        # log invalid requests
        # and ignore (return 200)
        if not hasattr(request.POST, "__getitem__"):
            logging.warning("invalid request type: %s, request: %s", request.content_type, request.POST)
            return True
        if "checkoutId" not in request.POST:
            logging.warning("invalid request: %s", request.POST)
            return True
        if not payment.transaction_id:
            payment.transaction_id = request.POST["checkoutId"]
            payment.save()
        if "checkoutStatus" in request.POST:
            if request.POST["checkoutStatus"] == "APPROVED":
                if self._capture:
                    payment.change_status(PaymentStatus.CONFIRMED)
                else:
                    payment.change_status(PaymentStatus.PREAUTH)
            elif request.POST["checkoutStatus"] == "CLOSED":
                if payment.status != PaymentStatus.REFUNDED:
                    payment.change_status(PaymentStatus.CONFIRMED)
                elif payment.status == PaymentStatus.PREAUTH and payment.captured_amount == 0:
                    payment.change_status(PaymentStatus.REFUNDED)
            elif not request.POST["checkoutStatus"] in ["OPEN", "PENDING"]:
                payment.change_status(PaymentStatus.ERROR)
        elif "refundStatus" in request.POST:
            if request.POST["refundStatus"] == "FAILED":
                logger.error("refund failed, try to recover")
                amount = self._retrieve_amount("/".join([self.path_refund.format(self.endpoint, payment.transaction_id), request.POST["transactionId"]]))
                if not amount:
                    logger.error("refund recovery failed")
                    payment.change_status(PaymentStatus.ERROR)
                    return False
                logger.error("refund recovery successfull")
                payment.captured_amount += amount
                payment.save()
                payment.change_status(PaymentStatus.ERROR)
        elif "captureStatus" in request.POST:
            # e.g. if not enough money or capture limit reached
            if request.POST["captureStatus"] == "FAILED":
                logger.error("capture failed, try to recover")
                amount = self._retrieve_amount("/".join([self.path_capture.format(self.endpoint, payment.transaction_id), request.POST["transactionId"]]))
                if not amount:
                    logger.error("capture recovery failed")
                    payment.change_status(PaymentStatus.ERROR)
                    return False
                logger.error("capture recovery successfull")
                payment.captured_amount -= amount
                payment.save()
                payment.change_status(PaymentStatus.ERROR)
        payment.save()
        return True

    def capture(self, payment, amount=None, final=True):
        if not amount:
            amount = payment.total
        if not amount:
            raise Exception(payment.total)
        if self.overcapture and amount > payment.total*Decimal("1.1"):
            return None
        elif not self.overcapture and amount > payment.total:
            return None
        headers = PaydirektProvider.header_default.copy()
        body = {
            "amount": amount.quantize(CENTS),
            "finalCapture": final,
            "callbackUrlStatusUpdates": payment.get_process_url()
        }
        json_response = self.send_request(self.path_capture.format(self.endpoint, payment.transaction_id),
                                          data=json.dumps(body, use_decimal=True),
                                          headers=headers)
        return amount

    def refund(self, payment, amount=None):
        if not amount:
            amount = payment.captured_amount
        if not amount:
            raise Exception(payment.total)
        headers = PaydirektProvider.header_default.copy()
        body = {
            "amount": amount.quantize(CENTS),
            "callbackUrlStatusUpdates": payment.get_process_url()
        }
        json_response = self.send_request(self.path_refund.format(self.endpoint, payment.transaction_id),
                                          data=json.dumps(body, use_decimal=True),
                                          headers=headers)
        if payment.status == PaymentStatus.PREAUTH and amount == payment.captured_amount:
            # logic, elsewise multiple signals are emitted CONFIRMED -> REFUNDED
            payment.change_status(PaymentStatus.REFUNDED)
            try:
                response = self.send_request(self.path_close.format(self.endpoint, payment.transaction_id),
                                             headers=headers)
            except Timeout:
                logger.error("Closing order failed")
        return amount
