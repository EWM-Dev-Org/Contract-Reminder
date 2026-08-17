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

REMINDER_MODE = os.environ.get("REMINDER_MODE", "summary").lower()

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SES_FROM_EMAIL = os.environ.get("SES_FROM_EMAIL")  # must be a verified SES identity

SOQL_QUERY = f"""
    SELECT Id, ContractNumber, AccountId, Account.Name, Status, StartDate, EndDate,
           ContractTerm, OwnerId, Owner.Email, Owner.Name,
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

def save_to_blob_storage(records: list[dict]) -> None:
    """
    Optional: persist the results to Azure Blob Storage.
    Uses the AzureWebJobsStorage connection string already available to the Function App.
    Skips silently if BLOB_CONTAINER_NAME is not configured.
    """
    container_name = os.environ.get("BLOB_CONTAINER_NAME")
    if not container_name:
        logging.info("BLOB_CONTAINER_NAME not set — skipping blob upload.")
        return
 
    conn_str = os.environ["AzureWebJobsStorage"]
    blob_service = BlobServiceClient.from_connection_string(conn_str)
 
    container_client = blob_service.get_container_client(container_name)
    if not container_client.exists():
        container_client.create_container()
 
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    blob_name = f"contracts/contracts_{timestamp}.json"
 
    container_client.upload_blob(
        name=blob_name,
        data=json.dumps(records, indent=2, default=str),
        overwrite=True,
    )
    logging.info(f"Uploaded {len(records)} records to blob: {blob_name}")
 
 
def _sigv4_sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
 
 
def _get_signature_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _sigv4_sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _sigv4_sign(k_date, region)
    k_service = _sigv4_sign(k_region, service)
    return _sigv4_sign(k_service, "aws4_request")
 
 
def send_email_via_ses(to_email: str, subject: str, body_html: str, body_text: str | None = None) -> None:
    """
    Send an email by calling the AWS SES v2 REST API directly
    (POST /v2/email/outbound-emails), signed with AWS Signature Version 4.
    No AWS SDK (boto3) dependency — just `requests` + stdlib hmac/hashlib.
 
    Requires:
      - SES_FROM_EMAIL: a verified SES sender identity
      - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY: IAM credentials with ses:SendEmail
      - AWS_REGION: the region the identity was verified in
      - AWS_SESSION_TOKEN (optional): required only if using temporary/STS credentials
    """
    if not SES_FROM_EMAIL:
        raise RuntimeError("SES_FROM_EMAIL app setting is not configured.")
 
    access_key = os.environ["AWS_ACCESS_KEY_ID"]
    secret_key = os.environ["AWS_SECRET_ACCESS_KEY"]
    session_token = os.environ.get("AWS_SESSION_TOKEN")  # only set for temporary/STS creds
 
    service = "ses"
    host = f"email.{AWS_REGION}.amazonaws.com"
    endpoint = f"https://{host}/v2/email/outbound-emails"
    canonical_uri = "/v2/email/outbound-emails"
    method = "POST"
 
    body_content = {
        "Subject": {"Data": subject, "Charset": "UTF-8"},
        "Body": {"Html": {"Data": body_html, "Charset": "UTF-8"}},
    }
    if body_text:
        body_content["Body"]["Text"] = {"Data": body_text, "Charset": "UTF-8"}
 
    payload = {
        "FromEmailAddress": SES_FROM_EMAIL,
        "Destination": {"ToAddresses": [to_email]},
        "Content": {"Simple": body_content},
    }
    request_body = json.dumps(payload)
    payload_hash = hashlib.sha256(request_body.encode("utf-8")).hexdigest()
 
    now = datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
 
    # --- Build the canonical request (headers must be lowercase & sorted) ---
    header_lines = [
        ("content-type", "application/json"),
        ("host", host),
        ("x-amz-date", amz_date),
    ]
    if session_token:
        header_lines.append(("x-amz-security-token", session_token))
    header_lines.sort(key=lambda kv: kv[0])
 
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in header_lines)
    signed_headers = ";".join(k for k, _ in header_lines)
 
    canonical_request = "\n".join([
        method,
        canonical_uri,
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
        "Content-Type": "application/json",
        "X-Amz-Date": amz_date,
        "Authorization": authorization_header,
    }
    if session_token:
        request_headers["X-Amz-Security-Token"] = session_token
 
    response = requests.post(endpoint, data=request_body, headers=request_headers, timeout=15)
 
    if response.status_code >= 300:
        raise RuntimeError(
            f"SES REST API call for {to_email} failed: "
            f"{response.status_code} {response.text}"
        )
 
    logging.info(f"Reminder email sent via SES REST API to {to_email} (subject: '{subject}').")
 
 
def get_reminder_value(record: dict) -> int | None:
    """Safely extract and coerce the reminder field to an int, or None if missing/invalid."""
    raw_value = record.get(REMINDER_FIELD_NAME)
    if raw_value is None:
        return None
    try:
        return int(raw_value)
    except (TypeError, ValueError):
        logging.warning(
            f"Contract {record.get('Id')} has non-integer {REMINDER_FIELD_NAME}: {raw_value!r}"
        )
        return None
 
 
def get_owner_email(record: dict) -> str | None:
    """Pull the related Owner's email from the query result, if present."""
    owner = record.get("Owner")
    if isinstance(owner, dict):
        return owner.get("Email")
    return None
 
 
def send_reminders(records: list[dict]) -> int:
    """
    Check each Contract's REMINDER_FIELD_NAME value against REMINDER_THRESHOLD
    and send email reminder(s) for the ones that qualify.
    Returns the number of contracts that triggered a reminder.
    """
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
 
    if REMINDER_MODE == "per_contract":
        for record, value in due:
            to_email = get_owner_email(record) or fallback_email
            if not to_email:
                logging.warning(
                    f"Contract {record.get('Id')} has no Owner email and no "
                    f"REMINDER_TO_EMAIL fallback configured — skipping."
                )
                continue
 
            subject = f"Contract Reminder: {record.get('ContractNumber')} — {REMINDER_FIELD_NAME} = {value}"
            body_html = f"""
                <p>Contract <b>{record.get('ContractNumber')}</b>
                (Account: {record.get('Account', {}).get('Name', 'N/A') if isinstance(record.get('Account'), dict) else 'N/A'})
                has {REMINDER_FIELD_NAME} = <b>{value}</b>, which is at or below the
                configured threshold of {REMINDER_THRESHOLD}.</p>
                <p>Status: {record.get('Status')}<br>
                End Date: {record.get('EndDate')}</p>
            """
            body_text = (
                f"Contract {record.get('ContractNumber')} has "
                f"{REMINDER_FIELD_NAME} = {value}, at or below the threshold of "
                f"{REMINDER_THRESHOLD}. Status: {record.get('Status')}. "
                f"End Date: {record.get('EndDate')}."
            )
            send_email_via_ses(to_email, subject, body_html, body_text)
 
    else:  # "summary" mode (default)
        if not fallback_email:
            raise RuntimeError(
                "REMINDER_MODE is 'summary' but REMINDER_TO_EMAIL is not configured."
            )
 
        rows = "".join(
            f"<tr><td>{r.get('ContractNumber')}</td><td>{r.get('Status')}</td>"
            f"<td>{r.get('EndDate')}</td><td>{value}</td></tr>"
            for r, value in due
        )
        subject = f"Contract Reminder: {len(due)} contract(s) at/below {REMINDER_FIELD_NAME} threshold ({REMINDER_THRESHOLD})"
        body_html = f"""
            <p>The following {len(due)} contract(s) have {REMINDER_FIELD_NAME}
            at or below the threshold of {REMINDER_THRESHOLD}:</p>
            <table border="1" cellpadding="6" cellspacing="0">
                <tr><th>Contract #</th><th>Status</th><th>End Date</th><th>{REMINDER_FIELD_NAME}</th></tr>
                {rows}
            </table>
        """
        text_rows = "\n".join(
            f"- {r.get('ContractNumber')} | {r.get('Status')} | "
            f"{r.get('EndDate')} | {REMINDER_FIELD_NAME}={value}"
            for r, value in due
        )
        body_text = (
            f"The following {len(due)} contract(s) have {REMINDER_FIELD_NAME} "
            f"at or below the threshold of {REMINDER_THRESHOLD}:\n\n{text_rows}"
        )
        send_email_via_ses(fallback_email, subject, body_html, body_text)
 
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
        save_to_blob_storage(records)
        reminders_sent = send_reminders(records)
        logging.info(
            f"DailyContractSync completed successfully. "
            f"{len(records)} records processed, {reminders_sent} reminder(s) triggered."
        )
 
    except Exception as exc:
        logging.error(f"DailyContractSync failed: {exc}", exc_info=True)
        raise  # re-raise so Azure marks the function execution as failed