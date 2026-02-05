import io
import json
import logging
import oci

from fdk import response


def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("Inside view Compartment function")
    
    try:
        cfg = ctx.Config()
        if cfg:
            namespace = cfg["namespace"]
            compartment_id = cfg["compartmentID"]
            frontendURL = cfg["frontendURL"]
    except (Exception, ValueError) as ex:
        logging.getLogger().info('Error in reading function arguments' + str(ex))
        
    returnText = "<html><body><h1>Object Storage Browser</h1><br>"
    
    try: 
        signer = oci.auth.signers.get_resource_principals_signer()
        object_storage_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
        #request_id = str(uuid.uuid4())
        
        list_buckets_response = object_storage_client.list_buckets(
            namespace_name=namespace,
            compartment_id=compartment_id,
            opc_client_request_id="OSBrowser-ListBuckets")
        bucketsResponse = json.loads(str(list_buckets_response.data))
        for bucket in bucketsResponse:
            bucketURL = frontendURL + "/bucket/" + bucket["name"]
            returnText = returnText + "<a href=" + bucketURL + ">" + bucket["name"] + "</a><br>"
            print(bucket["name"] + " : " + bucketURL)
    except (Exception, ValueError) as ex:
        logging.getLogger().info('Error Invoking Object Storage Client: ' + str(ex))
        return 'Error Invoking Object Storage Client: ' + str(ex)
    
    returnText = returnText + "<a href=\"/bucket/testURL\">Test Bucket</a>"
    returnText = returnText + "</body></html>"

    return response.Response(
        ctx, response_data=returnText,
        headers={"Content-Type": "text/html"}
    )
