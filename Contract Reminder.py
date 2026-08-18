import azure.functions as func
import logging
import os
import json
import hmac
import hashlib
import requests
from datetime import date, datetime, timezone
from simple_salesforce import Salesforce
from azure.storage.blob import BlobServiceClient

app = func.FunctionApp()

SCHEDULE = "0 0 6 * * *"

REMINDER_FIELD_NAME = "Contract_Expiration__c"

REMINDER_THRESHOLD = int(os.environ.get("REMINDER_THRESHOLD", "30"))

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SES_FROM_EMAIL = "e-sign@empirical.net"

SOQL_QUERY = f"""
    SELECT Id, ContractNumber, AccountId, Account.Name, Status, StartDate, EndDate,
           ContractTerm, OwnerId, Owner.Email, Owner.Name, Contract_Type__c,
           CreatedDate, LastModifiedDate, {REMINDER_FIELD_NAME}
    FROM Contract
"""

TODAY = date.today()
DAY = TODAY.day
REMAINDER = DAY % 2

def get_salesforce_client() -> Salesforce:
    domain = os.environ.get("SF_DOMAIN", "login")  # "login" for prod, "test" for sandbox

    if os.environ.get("SF_CLIENT_ID") and os.environ.get("SF_CLIENT_SECRET"):
        return Salesforce(
            username=os.environ["SF_USERNAME"],
            password=os.environ["SF_PASSWORD"],
            consumer_key=os.environ["SF_CLIENT_ID"],
            consumer_secret=os.environ["SF_CLIENT_SECRET"],
            domain=domain,
        )

    return Salesforce(
        username=os.environ["SF_USERNAME"],
        password=os.environ["SF_PASSWORD"],
        security_token=os.environ["SF_SECURITY_TOKEN"],
        domain=domain,
    )

def fetch_contracts(sf: Salesforce) -> list[dict]:
    result = sf.query_all(SOQL_QUERY)
    records = result.get("records", [])
    for r in records:
        r.pop("attributes", None)  # strip Salesforce metadata noise
    logging.info(f"Fetched {len(records)} Contract records from Salesforce.")
    return records

def _sigv4_sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _get_signature_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _sigv4_sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _sigv4_sign(k_date, region)
    k_service = _sigv4_sign(k_region, service)
    return _sigv4_sign(k_service, "aws4_request")

def _ses_rest_request(method: str, path: str, body_dict: dict | None = None) -> requests.Response:
    """
    Make a signed (SigV4) request against the SES v2 REST API.
    Used for both fetching templates (GET) and sending email (POST).
    No AWS SDK (boto3) dependency — just `requests` + stdlib hmac/hashlib.

    Requires:
      - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY: IAM creds with the relevant
        ses:* permission (ses:SendEmail, ses:GetEmailTemplate, etc.)
      - AWS_REGION: the region the identity/template lives in
      - AWS_SESSION_TOKEN (optional): required only for temporary/STS creds
    """
    access_key = os.environ["AWS_ACCESS_KEY_ID"]
    secret_key = os.environ["AWS_SECRET_ACCESS_KEY"]
    session_token = os.environ.get("AWS_SESSION_TOKEN")  # only set for temporary/STS creds

    service = "ses"
    host = f"email.{AWS_REGION}.amazonaws.com"
    endpoint = f"https://{host}{path}"

    request_body = json.dumps(body_dict) if body_dict is not None else ""
    payload_hash = hashlib.sha256(request_body.encode("utf-8")).hexdigest()

    now = datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    # --- Build the canonical request (headers must be lowercase & sorted) ---
    header_lines = [("host", host), ("x-amz-date", amz_date)]
    if body_dict is not None:
        header_lines.append(("content-type", "application/json"))
    if session_token:
        header_lines.append(("x-amz-security-token", session_token))
    header_lines.sort(key=lambda kv: kv[0])

    canonical_headers = "".join(f"{k}:{v}\n" for k, v in header_lines)
    signed_headers = ";".join(k for k, _ in header_lines)

    canonical_request = "\n".join([
        method,
        path,
        "",  # no query string
        canonical_headers,
        signed_headers,
        payload_hash,
    ])

    # --- Build the string to sign ---
    credential_scope = f"{date_stamp}/{AWS_REGION}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])

    # --- Derive the signing key and compute the signature ---
    signing_key = _get_signature_key(secret_key, date_stamp, AWS_REGION, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization_header = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    request_headers = {
        "X-Amz-Date": amz_date,
        "Authorization": authorization_header,
    }
    if body_dict is not None:
        request_headers["Content-Type"] = "application/json"
    if session_token:
        request_headers["X-Amz-Security-Token"] = session_token

    return requests.request(
        method,
        endpoint,
        data=request_body if body_dict is not None else None,
        headers=request_headers,
        timeout=15,
    )

def get_ses_email_template(template_name: str) -> dict:
    response = _ses_rest_request("GET", f"/v2/templates/{template_name}")

    if response.status_code == 404:
        raise RuntimeError(
            f"SES template '{template_name}' was not found in region {AWS_REGION}. "
            f"Create it first (see README) or fix SES Email Template."
        )
    if response.status_code >= 300:
        raise RuntimeError(
            f"Failed to fetch SES template '{template_name}': "
            f"{response.status_code} {response.text}"
        )

    return response.json()

def send_templated_email_via_ses(to_email: str, template_name: str, template_data: dict) -> None:
    if not SES_FROM_EMAIL:
        raise RuntimeError("SES_FROM_EMAIL app setting is not configured.")

    payload = {
        "FromEmailAddress": SES_FROM_EMAIL,
        "Destination": {"ToAddresses": [to_email]},
        "Content": {
            "Template": {
                "TemplateName": template_name,
                "TemplateData": json.dumps(template_data, default=str),
            }
        },
    }

    response = _ses_rest_request("POST", "/v2/email/outbound-emails", payload)

    if response.status_code >= 300:
        raise RuntimeError(
            f"SES templated send to {to_email} using template '{template_name}' "
            f"failed: {response.status_code} {response.text}"
        )

    logging.info(
        f"Reminder email sent via SES template '{template_name}' to {to_email}."
    )
 
def get_reminder_value(record: dict) -> int | None:
    raw_value = record.get(REMINDER_FIELD_NAME)
    if raw_value is None:
        return None
    try:
        if raw_value == REMAINDER:
            return int(raw_value)
        else:
            return None
    except (TypeError, ValueError):
        logging.warning(
            f"Contract {record.get('Id')} has non-integer {REMINDER_FIELD_NAME}: {raw_value!r}"
        )
        return None
 
def get_owner_email(record: dict) -> str | None:
    owner = record.get("Owner")
    if isinstance(owner, dict):
        return owner.get("Email")
    return None
 
def send_reminders(records: list[dict]) -> int:
    fallback_email = os.environ.get("REMINDER_TO_EMAIL")

    due = []
    for record in records:
        value = get_reminder_value(record)
        if value is not None and value <= REMINDER_THRESHOLD:
            due.append((record, value))

    if not due:
        logging.info(f"No contracts met the reminder threshold ({REMINDER_THRESHOLD}).")
        return 0

    logging.info(f"{len(due)} contract(s) met the reminder threshold ({REMINDER_THRESHOLD}).")

    

    for record, value in due:
        template_name = "EwmBlankTemplate"
        to_email = get_owner_email(record) or fallback_email
        if not to_email:
            logging.warning(
                f"Contract {record.get('Id')} has no Owner email and no "
                f"REMINDER_TO_EMAIL fallback configured — skipping."
            )
            continue
        if "DFS" in record.get("Contract_Type__c"):
            template_name = "DfsBlankTemplate"
            
        account = record.get("Account")
        template_data = {
            "contract_number": record.get("ContractNumber"),
            "account_name": account.get("Name") if isinstance(account, dict) else "N/A",
            "status": record.get("Status"),
            "end_date": record.get("EndDate"),
            "reminder_field_name": REMINDER_FIELD_NAME,
            "reminder_value": value,
            "threshold": REMINDER_THRESHOLD,
        }
        get_ses_email_template(template_name)
        send_templated_email_via_ses(to_email, template_name, template_data)

    return len(due)
 
@app.function_name(name="DailyContractSync")
@app.timer_trigger(schedule=SCHEDULE, arg_name="timer", run_on_startup=False, use_monitor=True)
def daily_contract_sync(timer: func.TimerRequest) -> None:
    utc_now = datetime.now(timezone.utc).isoformat()
 
    if timer.past_due:
        logging.warning("Timer trigger is running late.")
 
    logging.info(f"DailyContractSync started at {utc_now}")
 
    try:
        sf = get_salesforce_client()
        records = fetch_contracts(sf)
        reminders_sent = send_reminders(records)
        logging.info(
            f"DailyContractSync completed successfully. "
            f"{len(records)} records processed, {reminders_sent} reminder(s) triggered."
        )
 
    except Exception as exc:
        logging.error(f"DailyContractSync failed: {exc}", exc_info=True)
        raise  # re-raise so Azure marks the function execution as failed