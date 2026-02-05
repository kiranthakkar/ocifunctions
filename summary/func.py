import io
import json
import logging
import oci

from fdk import response

def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("Inside Summary Function")
    try:
        cfg = ctx.Config()
        aimodel = cfg["aimodel"]
        aiendpoint = cfg["aiendpoint"]
        if aimodel == None:
            aimodel = "cohere.command"
        if aiendpoint == None:
            aiendpoint = "https://inference.generativeai.us-chicago-1.oci.oraclecloud.com"
    except Exception as ex:
        logging.getLogger().error('ERROR: Missing configuration keys', str(ex))
        aimodel = "cohere.command"
        aiendpoint = "https://inference.generativeai.us-chicago-1.oci.oraclecloud.com"
    
    try:
        raw_body = data.getvalue()
        logging.getLogger().info("Raw body: '%s'", raw_body)
        body = json.loads(raw_body)
        namespace = body["data"]["additionalDetails"]["namespace"]
        bucketName = body["data"]["additionalDetails"]["bucketName"]
        resourceName = body["data"]["resourceName"]
        compartmentId = body["data"]["compartmentId"]
        logging.getLogger().info("Namespace: '%s'", namespace)
        logging.getLogger().info("Bucket Name: '%s'", bucketName)
        logging.getLogger().info("Resource Name: '%s'", resourceName)
        logging.getLogger().info("Compartment Id: '%s'", compartmentId)
    except (Exception, ValueError) as ex:
        logging.getLogger().error('Error parsing json payload: ' + str(ex))
        return 'Error parsing Event json payload: ' + str(ex)
    
    try: 
        signer = oci.auth.signers.get_resource_principals_signer()
        object_storage_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
        get_object_response = object_storage_client.get_object(
            namespace_name=namespace,
            bucket_name=bucketName,
            object_name=resourceName,
            opc_client_request_id="GetTranscribedObject")
        transcribedTest = get_object_response.data.text
        jsonText = json.loads(transcribedTest)
        transciptionArray = jsonText["transcriptions"]
        transcription = transciptionArray[0]["transcription"]
        
        generative_ai_inference_client = oci.generative_ai_inference.GenerativeAiInferenceClient(
            config={}, signer=signer, service_endpoint=aiendpoint)

        summarize_text_response = generative_ai_inference_client.summarize_text(
            summarize_text_details=oci.generative_ai_inference.models.SummarizeTextDetails(
                input=transcription,
                serving_mode=oci.generative_ai_inference.models.OnDemandServingMode(model_id=aimodel),
                compartment_id=compartmentId,
                is_echo=False,
                temperature=1,
                length="AUTO",
                format="AUTO",
                extractiveness="AUTO")).data
        logging.getLogger().info("Summarized Text: '%s'", summarize_text_response.summary)
        # Email the meeting minutes to team DL
        
    except (Exception, ValueError) as ex:
        logging.getLogger().info('Error Invoking Gen AI function: ' + str(ex))
        return 'Error Invoking Gen AI function: ' + str(ex)
        
    logging.getLogger().info("Summary Function Completed")
    return response.Response(
        ctx, response_data=json.dumps(
            {"message": "Summarization Job is completed successfully"}),
        headers={"Content-Type": "application/json"}
    )