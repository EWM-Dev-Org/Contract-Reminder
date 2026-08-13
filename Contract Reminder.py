import logging
import os
import json
from datetime import date
from typing import List, Dict

import azure.functions as func
import boto3
from botocore.exceptions import ClientError
from simple_salesforce import Salesforce, SalesforceAuthenticationFailed

BASE_PATH  = os.path.dirname(os.path.abspath(__file__))
FILE_PATH  = os.path.join(BASE_PATH, 'Credentials.json')

if os.path.exists(FILE_PATH):
    with open(FILE_PATH, 'r') as f:
        data = json.load(f)
else:
    print(f"File not found: {FILE_PATH}")
    print(f"Looking in: {os.getcwd()}")  

app = func.FunctionApp()

SCHEDULE = "0 0 8 * * *"
SEND_DELAY_SECONDS = 0.2

@app.function_name(name="ExpiredContractsReminder")
@app.schedule(schedule=SCHEDULE, arg_name="myTimer", run_on_startup=False,
              use_monitor=True)
def expired_contracts_reminder(myTimer: func.TimerRequest) -> None:
    logging.info("ExpiredContractsReminder: starting run")

    if myTimer.past_due:
        logging.warning("Timer trigger is past due!")

    try:
        contracts = get_expired_contracts()
    except SalesforceAuthenticationFailed as e:
        logging.error(f"Salesforce authentication failed: {e}")
        return
    except Exception as e:
        logging.error(f"Error querying Salesforce: {e}")
        return

    if not contracts:
        logging.info("No expired contracts found today. No email sent.")
        return

    try:
        send_reminder_email(contracts)
        logging.info(f"Reminder email sent for {len(contracts)} expired contract(s).")
    except ClientError as e:
        logging.error(f"SES send failed: {e.response['Error']['Message']}")
    except Exception as e:
        logging.error(f"Unexpected error sending email: {e}")


def get_expired_contracts() -> List[Dict]:
    """Query Salesforce for contracts whose EndDate has passed."""
    sf = Salesforce(
        username=data['username'],
        password=data['password'],
        security_token=data['security_token'],
        domain='test'
    )

    soql = """
        SELECT Id, ContractNumber, Status, Contract_Expiration__c, 
               Account.Name, Owner.Name
        FROM Contract
        WHERE Contract_Expiration__c != NULL
        ORDER BY CreatedDate DESC
    """
    result = sf.query_all(soql)
    return result.get("records", [])


def build_email_html(contracts: List[Dict]) -> str:
    today = date.today().isoformat()
    rows = ""
    for c in contracts:
        account_name = (c.get("Account") or {}).get("Name", "—")
        owner_name = (c.get("Owner") or {}).get("Name", "—")
        rows += f"""
        <tr>
            <td style="padding:6px 10px;border:1px solid #ddd;">{c.get('ContractNumber', c['Id'])}</td>
            <td style="padding:6px 10px;border:1px solid #ddd;">{account_name}</td>
            <td style="padding:6px 10px;border:1px solid #ddd;">{c.get('Contract_Expiration__c', '—')}</td>
            <td style="padding:6px 10px;border:1px solid #ddd;">{c.get('Status', '—')}</td>
            <td style="padding:6px 10px;border:1px solid #ddd;">{owner_name}</td>
        </tr>"""

    return f"""
    <html>
      <body style="font-family:Arial,sans-serif;">
        <h2>Expired Contracts Reminder — {today}</h2>
        <p>The following {len(contracts)} contract(s) have passed their end date
           and may need renewal, closure, or status updates in Salesforce:</p>
        <table style="border-collapse:collapse;font-size:14px;">
          <tr style="background:#f4f4f4;">
            <th style="padding:6px 10px;border:1px solid #ddd;">Contract #</th>
            <th style="padding:6px 10px;border:1px solid #ddd;">Account</th>
            <th style="padding:6px 10px;border:1px solid #ddd;">End Date</th>
            <th style="padding:6px 10px;border:1px solid #ddd;">Status</th>
            <th style="padding:6px 10px;border:1px solid #ddd;">Owner</th>
          </tr>
          {rows}
        </table>
        <p style="color:#888;font-size:12px;">Automated message from the Expired
           Contracts Reminder Azure Function.</p>
      </body>
    </html>
    """


def send_reminder_email(contracts: List[Dict]) -> None:
    sender = os.environ["SES_SENDER_EMAIL"]
    recipients = [r.strip() for r in os.environ["SES_RECIPIENT_EMAILS"].split(",") if r.strip()]
    region = os.environ.get("AWS_REGION", "us-east-1")

    ses = boto3.client(
        "ses",
        region_name=region,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    )

    html_body = build_email_html(contracts)
    subject = f"[Action Needed] {len(contracts)} Expired Salesforce Contract(s)"

    ses.send_email(
        Source=sender,
        Destination={"ToAddresses": recipients},
        Message={
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {
                "Html": {"Data": html_body, "Charset": "UTF-8"},
                "Text": {
                    "Data": f"{len(contracts)} contract(s) have expired. "
                            f"See Salesforce for details.",
                    "Charset": "UTF-8",
                },
            },
        },
    )