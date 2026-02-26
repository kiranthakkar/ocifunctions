import io
import json
import logging
import requests
import base64

from fdk import response

def generate_basic_auth_header(clientid,clientsecret):
    credentials = f"{clientid}:{clientsecret}"
    encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
    return f"Bearer {encoded_credentials}"

def read_group_from_source_id_domain(groupID, sourceIDDomain, sourceIDDomainClientID, sourceIDDomainClientSecret):
    authorization_header = generate_basic_auth_header(sourceIDDomainClientID, sourceIDDomainClientSecret)
    url = f"{sourceIDDomain}/admin/v1/Groups/{groupID}"
    querystring = {"attributes":"displayName, urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group:description"}
    headers = {
        'Authorization': authorization_header,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=30)
        response.raise_for_status()  # Raise an exception for HTTP errors
        group_details = response.json()
        return group_details
    except requests.exceptions.RequestException as e:
        logging.getLogger().error(f"Error fetching group details: {e}")
        return None
    
def create_group_in_target_id_domain(groupname, group_description, targetIDDomain, targetIDDomainClientID, targetIDDomainClientSecret):
    authorization_header = generate_basic_auth_header(targetIDDomainClientID, targetIDDomainClientSecret)
    url = f"{targetIDDomain}/admin/v1/Groups"
    request_body = {
        "displayName": groupname,
        "urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group": {
            "description": group_description
        },
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:Group",
            "urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group",
            "urn:ietf:params:scim:schemas:extension:custom:2.0:Group"
        ]
    }
    headers = {
        'Authorization': authorization_header,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.post(url, headers=headers, json=request_body, timeout=30)
        response.raise_for_status()  # Raise an exception for HTTP errors
        logging.getLogger().info(f"Group '{groupname}' created successfully in the target ID Domain.")
        if response.status_code == 201:
            return True
        else:
            logging.getLogger().error(f"Unexpected status code '{response.status_code}' received when creating group '{groupname}' in the target ID Domain.")
            return False
    except requests.exceptions.RequestException as e:
        logging.getLogger().error(f"Error creating group in target ID Domain: {e}")
        return False

def create_group(groupID, groupname, sourceIDDomain, sourceIDDomainClientID, sourceIDDomainClientSecret, targetIDDomain, targetIDDomainClientID, targetIDDomainClientSecret):
    
    group_details = read_group_from_source_id_domain(groupID, sourceIDDomain, sourceIDDomainClientID, sourceIDDomainClientSecret)
    if group_details is None:
        logging.getLogger().error(f"Group details not found for groupID '{groupID}' in source ID Domain. Group creation aborted.")
        return False
    
    group_description = group_details["urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group"]["description"]
    return create_group_in_target_id_domain(groupname, group_description, targetIDDomain, targetIDDomainClientID, targetIDDomainClientSecret)

def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("Inside Create Group function")
    try:
        raw_body = data.getvalue()
        logging.getLogger().info("Raw event body: '%s'", raw_body)
        body = json.loads(raw_body)
        logging.getLogger().info("Parsed event body: '%s'", body)
        groupname = body["data"]["additionalDetails"]["adminResourceName"]
        groupID = body["data"]["additionalDetails"]["adminResourceId"]
        logging.getLogger().info("Group Name: '%s'", groupname)
        logging.getLogger().info("Group ID: '%s'", groupID)
    except (Exception, ValueError) as ex:
        logging.getLogger().error(f'Error parsing json payload: {ex}')
        return response.Response(
            ctx, response_data=json.dumps(
                {"message": f"Error parsing Event json payload: {ex}"}),
            headers={"Content-Type": "application/json"}
        )
    
    try:
        cfg = ctx.Config()
        sourceIDDomain = cfg["sourceIDDomain"]
        sourceIDDomainClientID = cfg["sourceIDDomainClientID"]
        sourceIDDomainClientSecret = cfg["sourceIDDomainClientSecret"]
        targetIDDomain = cfg["targetIDDomain"]
        targetIDDomainClientID = cfg["targetIDDomainClientID"]
        targetIDDomainClientSecret = cfg["targetIDDomainClientSecret"]
    except Exception as ex:
        logging.getLogger().error(f'ERROR: Missing configuration keys: {ex}')
        return response.Response(
            ctx, response_data=json.dumps(
                {"message": f"ERROR: Missing configuration keys: {ex}"}),
            headers={"Content-Type": "application/json"}
        )

    # Fetch group from the source and create it in the target
    if (create_group(groupID, groupname, sourceIDDomain, sourceIDDomainClientID, sourceIDDomainClientSecret, targetIDDomain, targetIDDomainClientID, targetIDDomainClientSecret)):
        message = f"Group '{groupname}' is created in the target ID Domain."
    else:
        message = f"Group '{groupname}' creation failed in the target ID Domain. Check logs for details."
        
    return response.Response(
        ctx, response_data=json.dumps(
            {"message": message}),
        headers={"Content-Type": "application/json"}
    )
