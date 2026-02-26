import base64
import io
import json
import logging
import requests

from fdk import response

def generate_basic_auth_header(clientid,clientsecret):
    credentials = f"{clientid}:{clientsecret}"
    encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
    return f"Bearer {encoded_credentials}"

def read_user_from_source_id_domain(userID, sourceIDDomain, source_authorization_header):
    url = f"{sourceIDDomain}/admin/v1/Users/{userID}"
    authHeader = source_authorization_header
    querystring = {"attributes":"userName"}
    headers = {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=30)
        response.raise_for_status()  # Raise an exception for HTTP errors
        user_details = response.json()
        return user_details["userName"]
    except requests.exceptions.RequestException as e:
        logging.getLogger().error(f"Error fetching user details: {e}")
        return None

def read_user_from_target_id_domain(userName, targetIDDomain, target_authorization_header):
    url = f"{targetIDDomain}/admin/v1/Users"
    querystring = {"filter": f"userName eq \"{userName}\"", "attributes":"userName"}
    headers = {
        'Authorization': target_authorization_header,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=30)
        response.raise_for_status()  # Raise an exception for HTTP errors
        user_details = response.json()
        return user_details["Resources"][0]["id"]
    except requests.exceptions.RequestException as e:
        logging.getLogger().error(f"Error fetching user details: {e}")
        return None
    
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
    
def remove_user_from_group_in_target_id_domain(groupID, userID, targetIDDomain, target_authorization_header):
    url = f"{targetIDDomain}/admin/v1/Groups/{groupID}"
    request_body = {
        "schemas": [
            "urn:ietf:params:scim:api:messages:2.0:PatchOp"
        ],
        "Operations": [
            {
                "op": "remove",
                "path": f"members[value eq \"{userID}\"]"
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
        logging.getLogger().info(f"User with ID '{userID}' removed successfully from Group with ID '{groupID}' in the target ID Domain.")
        return True
    except requests.exceptions.RequestException as e:
        logging.getLogger().error(f"Error removing user from group in target ID Domain: {e}")
        return False

def remove_user_from_group(groupname, userID, sourceIDDomain, source_authorization_header, targetIDDomain, target_authorization_header):
    
    #Get UserName from source ID Domain using userID, then get userID in target ID Domain using the UserName. 
    #If the user does not exist in target ID Domain, create the user in target ID Domain and get the userID.
    userName = read_user_from_source_id_domain(userID, sourceIDDomain, source_authorization_header)
    if userName is None:
        logging.getLogger().error(f"User with ID '{userID}' not found in source ID Domain. Cannot proceed with removal from group.")
        return False
    userIDInTarget = read_user_from_target_id_domain(userName, targetIDDomain, target_authorization_header)
    if userIDInTarget is None:
        logging.getLogger().error(f"User '{userName}' does not exist in target ID Domain. Cannot remove user from group.")
        return False
    
    groupIDInTarget = read_group_from_target_ID_domain(groupname, targetIDDomain, target_authorization_header)
    if groupIDInTarget is None:
        logging.getLogger().error(f"Group with name '{groupname}' not found in target ID Domain. Cannot remove user from group.")
        return False

    return remove_user_from_group_in_target_id_domain(groupIDInTarget, userIDInTarget, targetIDDomain, target_authorization_header)

def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("Inside Remove User from Group function")
    try:
        raw_body = data.getvalue()
        body = json.loads(raw_body)
        groupname = body["data"]["additionalDetails"]["adminResourceName"]
        groupID = body["data"]["additionalDetails"]["adminResourceId"]
        userID = body["data"]["additionalDetails"]["adminRefResourceId"]
        userDisplayName = body["data"]["additionalDetails"]["adminRefResourceName"]
        logging.getLogger().info("Group Name: '%s'", groupname)
        logging.getLogger().info("Group ID: '%s'", groupID)
        logging.getLogger().info("User ID: '%s'", userID)
        logging.getLogger().info("User Display Name: '%s'", userDisplayName)
    except (Exception, ValueError) as ex:
        logging.getLogger().error(f"Error parsing json payload: {ex}")
        return response.Response(
            ctx, response_data=json.dumps({"message": f"Error parsing Event json payload: {ex}"}),
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
            ctx, response_data=json.dumps({"message": f"ERROR: Missing configuration keys: {ex}"}),
            headers={"Content-Type": "application/json"}
        )
    
    source_authorization_header = generate_basic_auth_header(sourceIDDomainClientID, sourceIDDomainClientSecret)
    target_authorization_header = generate_basic_auth_header(targetIDDomainClientID, targetIDDomainClientSecret)

    if(remove_user_from_group(groupname, userID, sourceIDDomain, source_authorization_header, targetIDDomain, target_authorization_header)):
        # Fetch group from the source and remove user from it in the target
        return response.Response(
            ctx, response_data=json.dumps(
                {"message": f"User '{userDisplayName}' is removed from Group '{groupname}' in the target ID Domain."}),
        headers={"Content-Type": "application/json"}
    )
    else:
        return response.Response(
            ctx, response_data=json.dumps(
                {"message": f"Failed to remove User '{userDisplayName}' from Group '{groupname}' in the target ID Domain."}),
        headers={"Content-Type": "application/json"}
    )

