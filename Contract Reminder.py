import azure.functions as func
import logging
import os
import json
import hmac
import hashlib
import requests
from datetime import datetime, timezone
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

def get_ses_client():
    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")

    if access_key and secret_key:
        return boto3.client(
            "ses",
            region_name=AWS_REGION,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

    return boto3.client("ses", region_name=AWS_REGION)


def send_email_via_ses(to_email: str, subject: str, body_html: str, body_text: str | None = None) -> None:
    if not SES_FROM_EMAIL:
        raise RuntimeError("SES_FROM_EMAIL app setting is not configured.")

    ses = get_ses_client()

    message = {
        "Subject": {"Data": subject, "Charset": "UTF-8"},
        "Body": {"Html": {"Data": body_html, "Charset": "UTF-8"}},
    }
    if body_text:
        message["Body"]["Text"] = {"Data": body_text, "Charset": "UTF-8"}

    try:
        ses.send_email(
            Source=SES_FROM_EMAIL,
            Destination={"ToAddresses": [to_email]},
            Message=message,
        )
    except ClientError as exc:
        raise RuntimeError(
            f"SES email to {to_email} failed: {exc.response['Error']['Message']}"
        ) from exc

    logging.info(f"Reminder email sent via SES to {to_email} (subject: '{subject}').")


def get_reminder_value(record: dict) -> int | None:
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
    owner = record.get("Owner")
    if isinstance(owner, dict):
        return owner.get("Email")
    return None

def send_reminders(records: list[dict]) -> int:
    fallback_email = os.environ.get("REMINDER_TO_EMAIL")

    due = []
    for record in records:
        value = get_reminder_value(record)
        if value is not None and value % 2 == REMAINDER:
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
        reminders_sent = send_reminders(records)
        logging.info(
            f"DailyContractSync completed successfully. "
            f"{len(records)} records processed, {reminders_sent} reminder(s) triggered."
        )

    except Exception as exc:
        logging.error(f"DailyContractSync failed: {exc}", exc_info=True)
        raise  # re-raise so Azure marks the function execution as failed