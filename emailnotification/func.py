import io
import json
import logging
import smtplib
import email.utils
from email.message import EmailMessage
import ssl

from fdk import response

def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("Inside Notification Email Function")
    try:
        raw_body = data.getvalue()
        body = json.loads(raw_body)
        eventType = body["eventType"]
        eventSource = body["source"]
        compartmentName = body["data"]["compartmentName"]
        resourceName = body["data"]["resourceName"]
        availabilityDomain = body["data"]["availabilityDomain"]
        eventTime = body["eventTime"]
    except (Exception, ValueError) as ex:
        logging.getLogger().error('Error parsing json payload: ' + str(ex))
        return 'Error parsing Event json payload: ' + str(ex)
    
    try:
        cfg = ctx.Config()
        sender = cfg["sender"]
        senderName = cfg["senderName"]
        recipient = cfg["recipient"]
        smtp_user = cfg["smtp_user"]
        smtp_password = cfg["smtp_password"]
        smtp_server = cfg["smtp_server"]
        
    except Exception as ex:
        logging.getLogger().error('ERROR: Missing configuration keys', str(ex))

    logging.getLogger().info("Inside Python Hello World function")
    return response.Response(
        ctx, response_data=json.dumps(
            {"message": "Hello {0}".format(name)}),
        headers={"Content-Type": "application/json"}
    )
