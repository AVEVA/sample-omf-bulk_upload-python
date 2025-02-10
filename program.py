# NOTE: this script was designed using the v1.2
# version of the OMF specification, as outlined here:
# https://docs.aveva.com/bundle/omf/page/1283983.html
# *************************************************************************************

# ************************************************************************
# Import necessary packages
# ************************************************************************

import enum
import gzip
import json
import requests
import traceback
import time
from urllib.parse import urlparse

# The version of the OMF messages
omf_version = '1.2'

# List of possible endpoint types
class EndpointTypes(enum.Enum):
    CDS = 'CDS'
    EDS = 'EDS'
    PI = 'PI'


def get_token(endpoint):
    '''Gets the token for the omfendpoint'''

    endpoint_type = endpoint["EndpointType"]
    # return an empty string if the endpoint is not an Cds type
    if endpoint_type != EndpointTypes.CDS:
        return ''

    if (('expiration' in endpoint) and (endpoint["expiration"] - time.time()) > 5 * 60):
        return endpoint["token"]

    # we can't short circuit it, so we must go retreive it.

    discovery_url = requests.get(
        endpoint["Resource"] + '/identity/.well-known/openid-configuration',
        headers={'Accept': 'application/json'},
        verify=endpoint["VerifySSL"])

    if discovery_url.status_code < 200 or discovery_url.status_code >= 300:
        discovery_url.close()
        raise Exception(f'Failed to get access token endpoint from discovery URL: {discovery_url.status_code}:{discovery_url.text}')

    token_endpoint = json.loads(discovery_url.content)["token_endpoint"]
    token_url = urlparse(token_endpoint)
    # Validate URL
    assert token_url.scheme == 'https'
    assert token_url.geturl().startswith(endpoint["Resource"])

    token_information = requests.post(
        token_url.geturl(),
        data={'client_id': endpoint["ClientId"],
              'client_secret': endpoint["ClientSecret"],
              'grant_type': 'client_credentials'},
        verify=endpoint["VerifySSL"])

    token = json.loads(token_information.content)

    if token is None:
        raise Exception('Failed to retrieve Token')

    __expiration = float(token["expires_in"]) + time.time()
    __token = token["access_token"]

    # cache the results
    endpoint["expiration"] = __expiration
    endpoint["token"] = __token

    return __token


def send_message_to_omf_endpoint(endpoint, message_type, message_omf_json, action='create'):
    '''Sends the request out to the preconfigured endpoint'''

    # Compress json omf payload, if specified
    compression = 'none'
    if endpoint["UseCompression"]:
        msg_body = gzip.compress(bytes(json.dumps(message_omf_json), 'utf-8'))
        compression = 'gzip'
    else:
        msg_body = json.dumps(message_omf_json)

    # Collect the message headers
    msg_headers = get_headers(endpoint, compression, message_type, action)

    # Send message to OMF endpoint
    endpoints_type = endpoint["EndpointType"]
    response = {}
    # If the endpoint is Cds
    if endpoints_type == EndpointTypes.CDS:
        response = requests.post(
            endpoint["OmfEndpoint"],
            headers=msg_headers,
            data=msg_body,
            verify=endpoint["VerifySSL"],
            timeout=endpoint["WebRequestTimeoutSeconds"]
        )
    # If the endpoint is EDS
    elif endpoints_type == EndpointTypes.EDS:
        response = requests.post(
            endpoint["OmfEndpoint"],
            headers=msg_headers,
            data=msg_body,
            timeout=endpoint["WebRequestTimeoutSeconds"]
        )
    # If the endpoint is PI
    elif endpoints_type == EndpointTypes.PI:
        response = requests.post(
            endpoint["OmfEndpoint"],
            headers=msg_headers,
            data=msg_body,
            verify=endpoint["VerifySSL"],
            timeout=endpoint["WebRequestTimeoutSeconds"],
            auth=(endpoint["Username"], endpoint["Password"])
        )

    # Check for 409, which indicates that a type with the specified ID and version already exists.
    if response.status_code == 409:
        return

    # response code in 200s if the request was successful!
    if response.status_code < 200 or response.status_code >= 300:
        print(msg_headers)
        response.close()
        print(
            f'Response from relay was bad. {message_type} message: {response.status_code} {response.text}.  Message holdings: {message_omf_json}')
        print()
        raise Exception(f'OMF message was unsuccessful, {message_type}. {response.status_code}:{response.text}')


def get_headers(endpoint, compression='', message_type='', action=''):
    '''Assemble headers for sending to the endpoint's OMF endpoint'''

    endpoint_type = endpoint["EndpointType"]

    msg_headers = {
        'messagetype': message_type,
        'action': action,
        'messageformat': 'JSON',
        'omfversion': omf_version
    }

    if(compression == 'gzip'):
        msg_headers["compression"] = 'gzip'

    # If the endpoint is Cds
    if endpoint_type == EndpointTypes.CDS:
        msg_headers["Authorization"] = f'Bearer {get_token(endpoint)}'
    # If the endpoint is PI
    elif endpoint_type == EndpointTypes.PI:
        msg_headers["x-requested-with"] = 'xmlhttprequest'

    # validate headers to prevent injection attacks
    validated_headers = {}

    for key in msg_headers:
        if key in {'Authorization', 'messagetype', 'action', 'messageformat', 'omfversion', 'x-requested-with', 'compression'}:
            validated_headers[key] = msg_headers[key]

    return validated_headers


def sanitize_headers(headers):
    validated_headers = {}

    for key in headers:
        if key in {'Authorization', 'messagetype', 'action', 'messageformat', 'omfversion', 'x-requested-with'}:
            validated_headers[key] = headers[key]

    return validated_headers


def get_json_file(filename):
    ''' Get a json file by the path specified relative to the application's path'''

    # Try to open the configuration file
    try:
        with open(
            filename,
            'r',
        ) as f:
            loaded_json = json.load(f)
    except Exception as error:
        print(f'Error: {str(error)}')
        print(f'Could not open/read file: {filename}')
        exit()

    return loaded_json


def get_appsettings():
    ''' Return the appsettings.json as a json object, while also populating base_endpoint, omf_endpoint, and default values'''

    # Try to open the configuration file
    endpoints = get_json_file('appsettings.json')["Endpoints"]

    # for each endpoint construct the check base and OMF endpoint and populate default values
    for endpoint in endpoints:
        endpoint["EndpointType"] = EndpointTypes(endpoint["EndpointType"])
        endpoint_type = endpoint["EndpointType"]

        # If the endpoint is Cds
        if endpoint_type == EndpointTypes.CDS:
            base_endpoint = f'{endpoint["Resource"]}/api/{endpoint["ApiVersion"]}' + \
                f'/tenants/{endpoint["TenantId"]}/namespaces/{endpoint["NamespaceId"]}'

        # If the endpoint is EDS
        elif endpoint_type == EndpointTypes.EDS:
            base_endpoint = f'{endpoint["Resource"]}/api/{endpoint["ApiVersion"]}' + \
                f'/tenants/default/namespaces/default'

        # If the endpoint is PI
        elif endpoint_type == EndpointTypes.PI:
            base_endpoint = endpoint["Resource"]

        else:
            raise ValueError('Invalid endpoint type')

        omf_endpoint = f'{base_endpoint}/omf'

        # add the base_endpoint and omf_endpoint to the endpoint configuration
        endpoint["BaseEndpoint"] = base_endpoint
        endpoint["OmfEndpoint"] = omf_endpoint

        # check for optional/nullable parameters
        if 'VerifySSL' not in endpoint or endpoint["VerifySSL"] == None:
            endpoint["VerifySSL"] = True

        if 'UseCompression' not in endpoint or endpoint["UseCompression"] == None:
            endpoint["UseCompression"] = True

        if 'WebRequestTimeoutSeconds' not in endpoint or endpoint["WebRequestTimeoutSeconds"] == None:
            endpoint["WebRequestTimeoutSeconds"] = 30

    return endpoints


def main(only_configure: bool = False):
    # Main program.  Seperated out so that we can add a test function and call this easily
    try:
        print("getting appsettings")
        endpoints = get_appsettings()

        if only_configure:
            return
        
        for endpoint in endpoints:
            if endpoint["Selected"]:
                print("sending types")
                send_message_to_omf_endpoint(endpoint, "type", get_json_file("type.json"))

                print("sending containers")
                send_message_to_omf_endpoint(endpoint, "container", get_json_file("container.json"))

                print("sending data")
                send_message_to_omf_endpoint(endpoint, "data", get_json_file("data.json"))

    except Exception as ex:
        print(("Encountered Error: {error}".format(error=ex)))
        print
        traceback.print_exc()
        print
        raise ex
    finally:
        print("done")


if __name__ == "__main__":
    main()
