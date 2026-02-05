import io
import json
import logging
import oci

from fdk import response

def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("Inside view Bucket function")
    
    try:
        cfg = ctx.Config()
        if cfg:
            namespace = cfg["namespace"]
            compartment_id = cfg["compartmentID"]
            frontendURL = cfg["frontendURL"]
    except (Exception, ValueError) as ex:
        logging.getLogger().info('Error in reading function arguments' + str(ex))
        
    returnText = "<html><body><h1>Object Storage Browser</h1><br>"
    returnText = returnText + "<h1>Objects in the Bucket are:</h1><br>"
    
    requestHeaders = ctx.Headers()
    bucketName = requestHeaders.get("bucketName")
    if(bucketName != None):
        logging.getLogger().info("Bucket Name: from Request header: " + bucketName)
    else:
        logging.getLogger().info("Bucket Name: from Request header: None")
    
    requestURL =  ctx.RequestURL()
    logging.getLogger().info("Request URL: " + requestURL)
    x = requestURL.split("/")
    bucketName = x[3]
    
    try: 
        signer = oci.auth.signers.get_resource_principals_signer()
        object_storage_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
        #request_id = str(uuid.uuid4())
        
        list_objects_response = object_storage_client.list_objects(
            namespace_name=namespace,
            bucket_name=bucketName,
            prefix="",  # optional
            opc_client_request_id="EXAMPLE-opc-client-request-id")

        # Get the data from response
        #print(list_objects_response.data.objects)
        objectsResponse = json.loads(str(list_objects_response.data.objects))
        for object in objectsResponse:
            objectName = object["name"]
            print("Object Name: " + objectName)
            if(objectName.endswith("/") == True):
                returnText = returnText + "Folder <a href=" + frontendURL + "/folder/" + object["name"] + ">" + object["name"] + "</a><br>"
                #objectURL = frontendURL + "/folder/" + object["name"]
                #print("This is folder: " + object["name"] + " : " + objectURL)
            else:
                returnText = returnText + "Object <a href=" + frontendURL + "/object/" + object["name"] + ">" + object["name"] + "</a><br>"
                #objectURL = frontendURL + "/object/" + object["name"]
                #print(object["name"] + " : " + objectURL)
    except (Exception, ValueError) as ex:
        logging.getLogger().info('Error Invoking Object Storage Client: ' + str(ex))
        return 'Error Invoking Object Storage Client: ' + str(ex)
    
    returnText = returnText + "</body></html>"
    return response.Response(
        ctx, response_data=returnText,
        headers={"Content-Type": "text/html"}
    )
