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

def read_user_from_source_id_domain(userID, sourceIDDomain, source_authorization_header):
    logging.getLogger().info("Fetching userName for the userID '%s' from source ID domain", userID)
    url = f"{sourceIDDomain}/admin/v1/Users/{userID}"
    querystring = {"attributes":"userName"}
    headers = {
        'Authorization': source_authorization_header,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=30)
        response.raise_for_status()  # Raise an exception for HTTP errors
        user_details = response.json()
        if "userName" in user_details:
            return user_details["userName"]
        return None
    except requests.exceptions.RequestException as e:
        logging.getLogger().error(f"Error fetching user details: {e}")
        return None

def read_user_from_target_id_domain(userName, targetIDDomain, target_authorization_header):
    logging.getLogger().info("Fetching userID for the userName '%s' from target ID domain", userName)
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
        if "Resources" in user_details and len(user_details["Resources"]) > 0:
            return user_details["Resources"][0]["id"]
        return None
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
    
def add_user_to_group_in_target_id_domain(groupID, userID, targetIDDomain, target_authorization_header):
    logging.getLogger().info(f"Adding user '{userID}' to Group '{groupID}' in the target ID Domain.")
    url = f"{targetIDDomain}/admin/v1/Groups/{groupID}"
    request_body = {
        "schemas": [
            "urn:ietf:params:scim:api:messages:2.0:PatchOp"
        ],
        "Operations": [
            {
            "op": "add",
            "path": "members",
            "value": [
                {
                "value": userID,
                "type": "User"
                }
            ]
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
        logging.getLogger().info(f"User '{userID}' added to Group '{groupID}' successfully in the target ID Domain.")
        return True
    except requests.exceptions.RequestException as e:
        logging.getLogger().error(f"Error adding user to group in target ID Domain: {e}")
        return False

def add_user_in_target_id_domain(userID,sourceIDDomain, source_authorization_header,  targetIDDomain, target_authorization_header):
    logging.getLogger().info(f"Adding user '{userID}' to target ID Domain as it does not exist there.")
    source_url = f"{sourceIDDomain}/admin/v1/Users/{userID}"
    target_url = f"{targetIDDomain}/admin/v1/Users"

    headers_for_source = {
        'Authorization': source_authorization_header,
        'Content-Type': 'application/json'
    }
    headers_for_target = {
        'Authorization': target_authorization_header,
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(source_url, headers=headers_for_source, timeout=30)
        response.raise_for_status()  # Raise an exception for HTTP errors
        source_user_details = response.json()

        body_user_details = {
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "name": {
                "givenName": source_user_details["name"]["givenName"],
                "familyName": source_user_details["name"]["familyName"]
            },
            "userName": source_user_details["userName"],
            "emails": [
            {
                "value": source_user_details["emails"][0]["value"],
                "type": "work",
                "primary": True
            }]}
        create_response = requests.post(target_url, headers=headers_for_target, json=body_user_details, timeout=30)
        create_response.raise_for_status()
        logging.getLogger().info(f"User '{userID}' created successfully in the target ID Domain.")
        return create_response.json()["id"]
    except requests.exceptions.RequestException as e:
        logging.getLogger().error(f"Error creating user in target ID Domain: {e}")
        return None

def add_user_to_group(groupname, userID, sourceIDDomain, source_authorization_header, targetIDDomain, target_authorization_header):
    
    #Get UserName from source ID Domain using userID, then get userID in target ID Domain using the UserName. 
    #If the user does not exist in target ID Domain, create the user in target ID Domain and get the userID.
    userName = read_user_from_source_id_domain(userID, sourceIDDomain, source_authorization_header)
    if userName is None:
        logging.getLogger().error(f"User with ID '{userID}' not found in source ID Domain. Cannot add user to group in target ID Domain.")
        return False
    userIDInTarget = read_user_from_target_id_domain(userName, targetIDDomain, target_authorization_header)
    if userIDInTarget is None:
        logging.getLogger().info(f"User '{userName}' not found in target ID Domain. Attempting to create the user in target ID Domain.")
        userIDInTarget = add_user_in_target_id_domain(userID, sourceIDDomain, source_authorization_header, targetIDDomain, target_authorization_header)
        if userIDInTarget is None:
            logging.getLogger().error(f"Failed to create user '{userName}' in target ID Domain. Cannot add user to group.")
            return False

    #Get groupID in target ID Domain using groupname and then add user to group in target ID Domain
    groupIDInTarget = read_group_from_target_ID_domain(groupname, targetIDDomain, target_authorization_header)
    if groupIDInTarget is None:
        logging.getLogger().error(f"Group with name '{groupname}' not found in target ID Domain. Cannot add user to group.")
        return False

    return add_user_to_group_in_target_id_domain(groupIDInTarget, userIDInTarget, targetIDDomain, target_authorization_header)

def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("Inside Add User to Group function")
    try:
        raw_body = data.getvalue()
        body = json.loads(raw_body)
        groupname = body["data"]["additionalDetails"]["adminResourceName"]
        userID = body["data"]["additionalDetails"]["adminRefResourceId"]
        userDisplayName = body["data"]["additionalDetails"]["adminRefResourceName"]
        logging.getLogger().info("Group Name: '%s'", groupname)
        logging.getLogger().info("User ID: '%s'", userID)
        logging.getLogger().info("User Display Name: '%s'", userDisplayName)
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

    source_authorization_header = generate_basic_auth_header(sourceIDDomainClientID, sourceIDDomainClientSecret)
    target_authorization_header = generate_basic_auth_header(targetIDDomainClientID, targetIDDomainClientSecret)
    
    if(add_user_to_group(groupname, userID, sourceIDDomain, source_authorization_header, targetIDDomain, target_authorization_header)):
        message = f"User '{userDisplayName}' is added to Group '{groupname}' in the target ID Domain."
    else:
        message = f"Failed to add User '{userDisplayName}' to Group '{groupname}' in the target ID Domain. Check logs for details."

    # Fetch group from the source and add user to it in the target
    return response.Response(
        ctx, response_data=json.dumps(
            {"message": message}),
        headers={"Content-Type": "application/json"}
    )
