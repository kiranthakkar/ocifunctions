import io
import logging
from urllib.parse import urlparse
from urllib.parse import parse_qs

from fdk import response


def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("Inside SAML Utility Function")
    
    try:
        cfg = ctx.Config()
        if cfg:
            idpNumbers = cfg["idpNumbers"]
            idp1 = cfg["idp1"]
            idp2 = cfg["idp2"]
            gateway = cfg["gateway"]
            logging.getLogger().info("IDP Numbers: " + idpNumbers)
    
    except (Exception, ValueError) as ex:
        logging.getLogger().info('Error in reading function arguments' + str(ex))
        
    try:
        requestURL =  ctx.RequestURL()
        logging.getLogger().info("Request URL: " + requestURL)
        
         # retrieving query string from the request URL, e.g. {"param1":["value"]}
        parsed_url = urlparse(requestURL)
        queryString = parse_qs(parsed_url.query)
        samlRequest = queryString["SAMLRequest"][0]
        relayState = queryString["RelayState"][0]
        #signAlg = queryString["SigAlg"][0]
        #signature = queryString["Signature"][0]
        logging.getLogger().info("samlRequest: " + samlRequest) 
        logging.getLogger().info("relayState: " + relayState)
        idp1URL = idp1
        idp2URL = idp2
        
        #samlXML = zlib.decompress(base64.b64decode(samlRequest), -15).decode('utf-8')
        
        #idp1SamlXML = samlXML.replace(gateway,idp1)
        #idp2SamlXML = samlXML.replace(gateway,idp2)
        
        #idp1EncodedSAML = base64.urlsafe_b64encode(idp1SamlXML.encode('utf-8')).decode('utf-8')
        #idp2EncodedSAML = base64.urlsafe_b64encode(idp2SamlXML.encode('utf-8')).decode('utf-8')
        
        #idp1URL = idp1 + "?SAMLRequest=" + idp1EncodedSAML + "&RelayState=" + relayState
        #idp2URL = idp2 + "?SAMLRequest=" + idp2EncodedSAML + "&RelatState=" + relayState
        
        logging.getLogger().info("IDP1 URL is: " + idp1URL) 
        logging.getLogger().info("IDP2 URL is: " + idp2URL)
    except (Exception, ValueError) as ex:
        logging.getLogger().info('Error in parsing Request Query Parameters: ' + str(ex))
        
    returnText = "<html><body><h1>SAML Utility</h1> \
        <a href=" + idp1URL + ">IDP1 SSO</a><br> \
        <a href=" + idp2URL + ">IDP2 SSO</a> \
        </body></html>"
    logging.getLogger().info("Returning Response: " + returnText)
            
    return response.Response(
        ctx, response_data=returnText,
        headers={"Content-Type": "text/html"}
    )
