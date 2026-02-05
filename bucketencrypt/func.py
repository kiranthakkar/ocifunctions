import io
import json
import logging
import oci

from fdk import response


def handler(ctx, data: io.BytesIO = None):
    try:
        body = json.loads(data.getvalue())
        print("Bucket namespace name: " + body["data"]["additionalDetails"]["namespace"])
        namespace = body["data"]["additionalDetails"]["namespace"]
        print("Bucket Name is: " + body["data"]["additionalDetails"]["bucketName"])
        bucket_name = body["data"]["additionalDetails"]["bucketName"]
    except (Exception, ValueError) as ex:
        logging.getLogger().info('error parsing json payload: ' + str(ex))
    
    try:
        cfg = ctx.Config()
        key_ocid = cfg["key_ocid"]
        if key_ocid == None:
            key_ocid = "ocid1.key.oc1.iad.dvslofaeaafzk.abuwcljtxvm65yz4zy25gacaa7yvp5g2itjz5cmtexw7kcdxzllvdxbemuja"
    except Exception as ex:
        logging.getLogger().error('ERROR: Missing configuration keys', str(ex))
        key_ocid = "ocid1.key.oc1.iad.dvslofaeaafzk.abuwcljtxvm65yz4zy25gacaa7yvp5g2itjz5cmtexw7kcdxzllvdxbemuja"

    try:
        signer = oci.auth.signers.get_resource_principals_signer()
        client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)

        # Update the bucket to use the customer managed key
        bucket_details = client.get_bucket(namespace, bucket_name).data
        key_used_before = bucket_details.kms_key_id
        logging.getLogger().info(f"Key used before update: {key_used_before}")

        if(key_used_before == None):
            logging.getLogger().info("Bucket is currently using Oracle managed key. Proceeding with update.")
            update_bucket_details=oci.object_storage.models.UpdateBucketDetails(
                namespace=namespace,
                name=bucket_name,
                compartment_id=bucket_details.compartment_id,
                kms_key_id=key_ocid)
            client.update_bucket(
                namespace_name=namespace, 
                bucket_name=bucket_name, 
                update_bucket_details=update_bucket_details,
                opc_client_request_id="UpdateBucketWithCMK")
            logging.getLogger().info(f"Bucket updated to use customer managed key: {key_ocid}")
        else:
            logging.getLogger().info("Bucket is already using a customer managed key. No update needed.")
            return response.Response(
                ctx, response_data=json.dumps(
                    {"message": "Bucket is already using a customer managed key."}),
                headers={"Content-Type": "application/json"}
            )
        
    except Exception as ex:
        logging.getLogger().info(f"Error updating bucket with customer managed key: {str(ex)}")

    return response.Response(
        ctx, response_data=json.dumps(
            {"message": "Bucket updated successfully to use customer managed key."}),
        headers={"Content-Type": "application/json"}
    )