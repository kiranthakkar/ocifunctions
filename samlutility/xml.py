import base64
import zlib

idp1 = "https://idcs-e896cabd603a49f0895bc1cc38d28996.identity.oraclecloud.com/fed/v1/idp/sso"
gateway = "https://aersy4hryjkku7b64w5th42qw4.apigateway.us-ashburn-1.oci.customer-oci.com/saml/idp"
relayStete = "SomeState"

samlRequest = "hVNtb5swEP4ryP0MGEOSxQqpokWRMjXbunRTt2/GPoJXg6ltRumvn0mE1E1q+9Gn5+55ufPq+qlWwR8wVuomR0mEUQAN10I2pxx9v9uFH1BgHWsEU7qBHA1g0fV6ZVmtWrrpXNV8g8cOrAv8oMbSpxnGOepMQzWz0tKG1WCp4/S4OdxQEmHaGl1K5YvMOSOLzgG9901oGmBljirnWhrHfd9HfRppc4oJxkl8f7g58gpqFspmFMVh6hr1vE3LrAXjvMupxdt8lQhnsQd5xNWEFlaeXoHjGC9H+Ai5eimofTcIp7lWKNhpw+EcZo5Kpqy3tfWRyoa581pGWut5md/TkFVm+P3w0C2KedbPXJWRxz6LWCtPzEHPhqizIbNV4anDJNJcRryzTtdgwvND1/EoLpaiRcHe2g725zBdjggmWYiXIVnckZSSGSXLXyj4MV0HGa9jv82RFOGmeuZQfLltDz/3SWJSdbs4LpPdM3zKQnS5D3oebkZ3NXNvZzFW/NTyDPWrcdINaD35loLbsChTXMxTKCEhWZFiloF/L8WcEI4LPoukuPT5vTCugCvdidEuzbI0LkGs4heqphP+7In3269aST4EG6V0/9GADzJHznSA3hWfRMn/4msm1UYIA9aieH1h/fevrP8C"

samlXML = zlib.decompress(base64.b64decode(samlRequest), -15).decode('utf-8')

print(samlXML)

idp1SamlXML = samlXML.replace(gateway,idp1)
        
idp1EncodedSAML = base64.b64encode(idp1SamlXML.encode('utf-8'))
assertion = base64.urlsafe_b64encode(idp1SamlXML.encode('utf-8')).decode('utf-8')

print(idp1EncodedSAML)



idp1URL = idp1 + "?SAMLRequest=" + assertion + "&RelayState=" + relayStete

print(idp1URL)
