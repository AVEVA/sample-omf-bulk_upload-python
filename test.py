
import requests
import program as program
import sys
import traceback
import time
import json


def suppress_error(call):
    try:
        call()
    except Exception as e:
        print(f"Encountered Error: {e}")


def send_type_delete(endpoint):
    program.send_message_to_omf_endpoint(endpoint, "type", program.get_json_file("type.json"), "delete")


def send_container_delete(endpoint):
    program.send_message_to_omf_endpoint(endpoint, "container", program.get_json_file("container.json"), "delete")


def check_data(endpoint):
    global app_config
    if endpoint["EndpointType"] == program.EndpointTypes.OCS:
        check_last_ocs_val(endpoint)
    # don't have to check others as they are sync and we get instant feedback on success from the app itself


def check_last_ocs_val(endpoint):
    '''Wait for data to populate in OCS'''
    time.sleep(10)

    global app_config
    
    msg_headers = {
        "Authorization": "Bearer %s" % program.get_token(endpoint),
    }

    # validate headers to prevent injection attacks
    validated_headers = {}

    for key in msg_headers:
        if key in {'Authorization', 'messagetype', 'action', 'messageformat', 'omfversion', 'x-requested-with', 'compression'}:
            validated_headers[key] = msg_headers[key]

    url = endpoint['OmfEndpoint'].split(
        '/omf')[0] + '/streams/Tank1Measurements/data/last'
    response = requests.get(
        url,
        headers=validated_headers,
        verify=endpoint['VerifySSL']
    )

    # response code in 200s if the request was successful!
    if response.status_code < 200 or response.status_code >= 300:
        print(validated_headers)
        response.close()
        print('Response from was bad.  message: {0} {1} {2}.'.format(
            response.status_code, url, response.text))
        print()
        raise Exception("Get value was unsuccessful, {url}. {status}:{reason}".format(
            url=url, status=response.status_code, reason=response.text))


def test_main(only_delete: bool = False):
    global app_config
    '''Tests to make sure the sample runs as expected'''

    try:
        program.main(only_delete)
        endpoints = program.get_appsettings()

        if(not only_delete):
            for endpoint in endpoints:
                if endpoint["Selected"]:
                    check_data(endpoint)

    except Exception as ex:
        print(f'Encountered Error: {ex}.')
        print
        traceback.print_exc()
        print
        raise ex

    finally:
        print('Deletes')
        print

        endpoints = program.get_appsettings()

        for endpoint in endpoints:
            if endpoint["Selected"]:
                suppress_error(lambda: send_container_delete(endpoint))
                suppress_error(lambda: send_type_delete(endpoint))


if len(sys.argv) > 1:
    only_delete = sys.argv[1]
else:
    only_delete = False

if __name__ == "__main__":
    test_main(only_delete)
