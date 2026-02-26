import base64
import io
import json
import logging
import requests

from creategroup.func import create_group_in_target_id_domain
from fdk import response

def generate_basic_auth_header(clientid,clientsecret):
    credentials = f"{clientid}:{clientsecret}"
    encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
    return f"Bearer {encoded_credentials}"

def read_group_from_source_id_domain(groupname, sourceIDDomain, source_authorization_header):
    url = f"{sourceIDDomain}/admin/v1/Groups"
    querystring = {"filter": f"displayName eq \"{groupname}\"", "attributes": "displayName, urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group:description"}
    headers = {
        'Authorization': source_authorization_header,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=30)
        response.raise_for_status()  # Raise an exception for HTTP errors
        group_details = response.json()
        if group_details and "Resources" in group_details and len(group_details["Resources"]) > 0:
            return group_details
        return None
    except requests.exceptions.RequestException as e:
        logging.getLogger().error(f"Error fetching group details: {e}")
        return None
    
def read_group_id(groupname, targetIDDomain, target_authorization_header):
    url = f"{targetIDDomain}/admin/v1/Groups"
    querystring = {"filter": f"displayName eq \"{groupname}\"", "attributes": "displayName"}
    headers = {
        'Authorization': target_authorization_header,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=30)
        response.raise_for_status()  # Raise an exception for HTTP errors
        group_details = response.json()
        if group_details and "Resources" in group_details and len(group_details["Resources"]) > 0:
            groupID = group_details["Resources"][0]["id"]
            return groupID
        return None
    except requests.exceptions.RequestException as e:
        logging.getLogger().error(f"Error fetching group details: {e}")
        return None

def update_group_in_target_id_domain(groupID, groupname, group_description, targetIDDomain, target_authorization_header):
    logging.getLogger().info(f"Group description changed. Calling function to update Display Name")
    url = f"{targetIDDomain}/admin/v1/Groups/{groupID}"
    request_body = {
    "schemas": [
        "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    ],
    "Operations": [
        {
        "op": "replace",
        "path": "displayName",
        "value": groupname
        },
        {
        "op": "replace",
        "path": "urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group:description",
        "value": group_description
        }
    ]
    }
    headers = {
        'Authorization': target_authorization_header,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.patch(url, headers=headers, json=request_body, timeout=30)
        response.raise_for_status()  # Raise an exception for HTTP errors
        if response.status_code == 200 or response.status_code == 204 or response.status_code == 201:
            logging.getLogger().info(f"Group '{groupname}' updated successfully in the target ID Domain.")
            return True
        else:
            logging.getLogger().error(f"Unexpected status code '{response.status_code}' received when updating group '{groupname}' in the target ID Domain.")
            return False
    except requests.exceptions.RequestException as e:
        logging.getLogger().error(f"Error updating group '{groupname}' in the target ID Domain: {e}")
        return False

def updateGroupDescription(groupname,sourceIDDomain, source_authorization_header, targetIDDomain, target_authorization_header):
    group_details = read_group_from_source_id_domain(groupname, sourceIDDomain, source_authorization_header)
    if group_details and "Resources" in group_details and len(group_details["Resources"]) > 0:
        group_description = group_details["Resources"][0].get("urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group", {}).get("description", "")
        groupID = read_group_id(groupname, targetIDDomain, target_authorization_header)
        if groupID:
            update_group_in_target_id_domain(groupID, groupname, group_description, targetIDDomain, target_authorization_header)
            return True
        else:
            logging.getLogger().error(f"Group '{groupname}' not found in the target ID Domain. Cannot update description in the target ID Domain.")
            return False
    else:
        logging.getLogger().error(f"Group '{groupname}' not found in the source ID Domain. Cannot update description in the target ID Domain.")
        return False

def changeGroupName(groupOldName, groupNewName, sourceIDDomain, source_authorization_header, targetIDDomain, target_authorization_header):
    logging.getLogger().info(f"Group display name is changed. No change in group required.")
    group_details = read_group_from_source_id_domain(groupNewName, sourceIDDomain, source_authorization_header)
    if group_details and "Resources" in group_details and len(group_details["Resources"]) > 0:
        group_description = group_details["Resources"][0].get("urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group", {}).get("description", "")
        groupID = read_group_id(groupOldName, targetIDDomain, target_authorization_header)
        if groupID:
            update_group_in_target_id_domain(groupID, groupNewName, group_description, targetIDDomain, target_authorization_header)
            return True
        else:
            logging.getLogger().error(f"Group '{groupOldName}' not found in the target ID Domain. Cannot update display name in the target ID Domain.")
            return False
    else:
        logging.getLogger().error(f"Group '{groupNewName}' not found in the source ID Domain. Cannot update display name in the target ID Domain.")
        return False


def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("Inside Update Group function")
    try:
        cfg = ctx.Config()
        sourceIDDomain = cfg["sourceIDDomain"]
        sourceIDDomainClientID = cfg["sourceIDDomainClientID"]
        sourceIDDomainClientSecret = cfg["sourceIDDomainClientSecret"]
        targetIDDomain = cfg["targetIDDomain"]
        targetIDDomainClientID = cfg["targetIDDomainClientID"]
        targetIDDomainClientSecret = cfg["targetIDDomainClientSecret"]
    except Exception as ex:
        logging.getLogger().error('ERROR: Missing configuration keys', str(ex))
        return response.Response(
            ctx, response_data=json.dumps(
                {"message": f"ERROR: Missing configuration keys: {ex}"}),
            headers={"Content-Type": "application/json"}
        )
    
    try:
        raw_body = data.getvalue()
        body = json.loads(raw_body)
        geoupsAdded = body["data"]["additionalDetails"]["adminValuesAdded"]["members"]
        groupsRemoved = body["data"]["additionalDetails"]["adminValuesRemoved"]["members"]
        if len(geoupsAdded) > 0 or len(groupsRemoved) > 0:
            logging.getLogger().info(f"Members are added or removed from the group. No change in group required.")
            return response.Response(
                ctx, response_data=json.dumps(
                    {"message": "Members are added or removed from the group. No change in group required."}),
                headers={"Content-Type": "application/json"}
            )
        groupOldName = body["data"]["additionalDetails"]["adminValuesAdded"]["displayName"]
        groupNewName = body["data"]["additionalDetails"]["adminValuesRemoved"]["displayName"]
        if groupOldName != groupNewName:
            logging.getLogger().info(f"Group display name is changed. No change in group required.")
            changeStatus = changeGroupName(groupOldName, groupNewName, sourceIDDomain, generate_basic_auth_header(sourceIDDomainClientID, sourceIDDomainClientSecret), targetIDDomain, generate_basic_auth_header(targetIDDomainClientID, targetIDDomainClientSecret))
        
        else:
            logging.getLogger().info(f"Group description changed. Calling function to update Display Name")
            changeStatus = updateGroupDescription(groupNewName, sourceIDDomain, generate_basic_auth_header(sourceIDDomainClientID, sourceIDDomainClientSecret), targetIDDomain, generate_basic_auth_header(targetIDDomainClientID, targetIDDomainClientSecret))
    except (Exception, ValueError) as ex:
        logging.getLogger().error('Error parsing json payload: ' + str(ex))
        return 'Error parsing Event json payload: ' + str(ex)
    
    if changeStatus:
        message = f"Group '{groupNewName}' is updated in the target ID Domain."
    else:
        message = f"Group '{groupNewName}' update failed in the target ID Domain. Check logs for details."
    
    # Fetch group from the source and update it in the target
    return response.Response(
        ctx, response_data=json.dumps(
            {"message": message}),
        headers={"Content-Type": "application/json"}
    )