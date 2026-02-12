from google.cloud import storage
import oci
import requests
from google.auth import identity_pool
import logging
import json
import io
from fdk import response


class OCITokenSupplier(identity_pool.SubjectTokenSupplier):
    """Custom supplier to fetch an OCI OIDC token via POST or OCI SDK."""

    def __init__(self, iam_domain_url): 
        self.iam_domain_url = iam_domain_url
    
    def get_subject_token(self, context, request):
        logging.getLogger().info("Get Subject Token called for RPST token exchange")
        # Use OCI resource principal signer to authenticate the token exchange call.
        signer = oci.auth.signers.get_resource_principals_signer()
        # Build OCI IAM token endpoint and token exchange payload.
        oci_url = f'https://{self.iam_domain_url}/oauth2/v1/token'
        oci_data = 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange&scope=urn:opc:idm:__myscopes__&requested_token_type=urn:ietf:params:oauth:token-type:access_token'

        headers = {'Content-type': 'application/x-www-form-urlencoded'}
        req = requests.Request('POST', url=oci_url, headers=headers, data=oci_data, auth=signer)
        r = req.prepare()

        # Perform the HTTP request and extract the access token from the response.
        s = requests.Session()
        response = s.send(r)
        access_token = response.json()['access_token']
        logging.getLogger().info(f"Access Token generated for RPST: {access_token}")
        return access_token

def handler(ctx, data: io.BytesIO = None):
    try:
        # Read function configuration for OCI and GCP settings.
        cfg = ctx.Config()
        iam_domain_url = cfg["OCI_IAM_DOMAIN_URL"]
        gcp_project_id = cfg["GCP_PROJECT_ID"]
        gcp_audience = cfg["GCP_AUDIENCE"]
        gcp_impersonation_url = cfg["GCP_IMPERSONATION_URL"]
    except Exception as ex:
        logging.getLogger().error('ERROR: Missing configuration keys', str(ex))

    # Supply an OCI access token as the subject token for GCP workload identity.
    supplier = OCITokenSupplier(iam_domain_url=iam_domain_url)

    # Configure GCP identity pool credentials using the OCI subject token.
    credentials = identity_pool.Credentials(
        credential_source=None,
        audience=gcp_audience,
        subject_token_type="urn:ietf:params:oauth:token-type:jwt",
        token_url="https://sts.googleapis.com/v1/token",
        service_account_impersonation_url=gcp_impersonation_url,
        subject_token_supplier=supplier
    )

    # Access GCS using the federated credentials and list buckets.
    storage_client = storage.Client(credentials=credentials, project=gcp_project_id)
    buckets = list(storage_client.list_buckets())
    print(buckets)
    logging.getLogger().info('Buckets received are ' + str(buckets))

    logging.getLogger().info("buckets are retrieved successfully using RPST token exchange")
    return response.Response(
        ctx, response_data=json.dumps(
            {"message": "Hello {0}".format(buckets)}),
        headers={"Content-Type": "application/json"}
    )
