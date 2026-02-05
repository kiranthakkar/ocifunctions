import io
import json
import logging
import oci

from fdk import response

def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("Inside Transcribe Function")
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
        cfg = ctx.Config()
        targetbucket = cfg["targetbucket"]
        if targetbucket == None:
            targetbucket = bucketName
    except Exception as ex:
        logging.getLogger().error('ERROR: Missing configuration keys', str(ex))
        targetbucket = bucketName
    
    try:
        signer = oci.auth.signers.get_resource_principals_signer()
        ai_speech_client = oci.ai_speech.AIServiceSpeechClient(config={}, signer=signer)
        
        create_transcription_job_response = ai_speech_client.create_transcription_job(
            create_transcription_job_details=oci.ai_speech.models.CreateTranscriptionJobDetails(
                compartment_id=compartmentId,
                input_location=oci.ai_speech.models.ObjectListInlineInputLocation(
                    location_type="OBJECT_LIST_INLINE_INPUT_LOCATION",
                    object_locations=[oci.ai_speech.models.ObjectLocation(
                        namespace_name=namespace,
                        bucket_name=bucketName,
                        object_names=[resourceName])]),
                output_location=oci.ai_speech.models.OutputLocation(
                    namespace_name=namespace,
                    bucket_name=targetbucket),
                additional_transcription_formats=["SRT"],
                normalization=oci.ai_speech.models.TranscriptionNormalization(
                    is_punctuation_enabled=False,
                    filters=[
                        oci.ai_speech.models.ProfanityTranscriptionFilter(
                            type="PROFANITY",
                            mode="MASK")])))
    except (Exception, ValueError) as ex:
        logging.getLogger().info('error parsing json payload: ' + str(ex))
    
    logging.getLogger().info("Transcribe Function Completed")
    return response.Response(
        ctx, response_data=json.dumps(
            {"message": "Transcription job completed successfully"}),
        headers={"Content-Type": "application/json"}
    )