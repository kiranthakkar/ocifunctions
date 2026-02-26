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
    
def read_group_from_target_ID_domain(groupname, targetIDDomain, target_authorization_header):
    logging.getLogger().info("Fetching groupID for the groupName '%s' from target ID domain", groupname)
    url = f"{targetIDDomain}/admin/v1/Groups"
    querystring = {"filter": f"displayName eq \"{groupname}\"", "attributes":"displayName"}
    headers = {
        'Authorization': target_authorization_header,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=30)
        response.raise_for_status()  # Raise an exception for HTTP errors
        group_details = response.json()
        return group_details["Resources"][0]["id"] if group_details["totalResults"] > 0 else None
    except requests.exceptions.RequestException as e:
        logging.getLogger().error(f"Error fetching group details: {e}")
        return None
    
def delete_group_in_target_id_domain(groupID, targetIDDomain, target_authorization_header):
    url = f"{targetIDDomain}/admin/v1/Groups/{groupID}"
    headers = {
        'Authorization': target_authorization_header,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.delete(url, headers=headers, timeout=30)
        response.raise_for_status()  # Raise an exception for HTTP errors
        logging.getLogger().info(f"Group with ID '{groupID}' deleted successfully in the target ID Domain.")
        return True
    except requests.exceptions.RequestException as e:
        logging.getLogger().error(f"Error deleting group with ID '{groupID}': {e}")
        return False

def delete_group(groupname, targetIDDomain, target_authorization_header):
    groupID = read_group_from_target_ID_domain(groupname, targetIDDomain, target_authorization_header)
    if groupID is None:
        logging.getLogger().info(f"Group '{groupname}' not found in the target ID Domain. No deletion needed.")
        return False
    return delete_group_in_target_id_domain(groupID, targetIDDomain, target_authorization_header)

def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("Inside Delete Group function")
    try:
        raw_body = data.getvalue()
        body = json.loads(raw_body)
        groupname = body["data"]["additionalDetails"]["adminResourceName"]
        logging.getLogger().info("Group Name: '%s'", groupname)
    except (Exception, ValueError) as ex:
        logging.getLogger().error(f'Error parsing json payload: {ex}')
        return response.Response(
            ctx, response_data=json.dumps(
                {"message": f"Error parsing json payload: {ex}"}),
            headers={"Content-Type": "application/json"}
        )
    
    try:
        cfg = ctx.Config()
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
    
    target_authorization_header = generate_basic_auth_header(targetIDDomainClientID, targetIDDomainClientSecret)
    
    if(delete_group(groupname, targetIDDomain, target_authorization_header)):
        logging.getLogger().info(f"Group '{groupname}' is deleted in the target ID Domain.")
        message = f"Group '{groupname}' is deleted in the target ID Domain."
    else:
        logging.getLogger().info(f"Group '{groupname}' could not be deleted in the target ID Domain.")
        message = f"Group '{groupname}' could not be deleted in the target ID Domain."

    # Fetch group from the source and delete it in the target
    return response.Response(
        ctx, response_data=json.dumps(
            {"message": message}),
        headers={"Content-Type": "application/json"}
    )
