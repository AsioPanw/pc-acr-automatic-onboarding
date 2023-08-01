__author__ = "Simon Melotte"

import os
import json
import requests

from dotenv import load_dotenv


def add_container_registries(base_url, token, existing_container_registries, acr_list, account):
    accountId, accountName = account  # Unpack account tuple
    url = f"{base_url}/api/v1/settings/registry?project=Central+Console&scanLater=false"
    headers = {"content-type": "application/json; charset=UTF-8",
               "Authorization": "Bearer " + token}

    for registry in acr_list['resources']:
        if registry['accountId'] == accountId:
            # Check if the registry already exists
            if not any(existing_registry['registry'] == registry['name'] + ".azurecr.io" for existing_registry in existing_container_registries['specifications']):
                new_registry = {
                    "version": "azure",
                    "registry": registry['name'] + ".azurecr.io",
                    "namespace": "",
                    "repository": "*",
                    "tag": "",
                    "credentialID": f"{accountId}-servicekey",
                    "os": "linux",
                    "harborDeploymentSecurity": False,
                    "collections": ["All"],
                    "cap": 5,
                    "scanners": 2,
                    "versionPattern": "",
                    "gitlabRegistrySpec": {}
                }

                # Add the new registry to the specifications list
                existing_container_registries['specifications'].append(new_registry)
                print(f"Registry to be added: {registry['name']}.azurecr.io")
            else:
                print(f"Registry {registry['name']}.azurecr.io already exists in Prisma Cloud")

    # Convert the updated registries to JSON
    payload = json.dumps(existing_container_registries)

    try:
        response = requests.request("PUT", url, headers=headers, data=payload)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except requests.exceptions.RequestException as err:
        print("Oops! An exception occurred in add_container_registries, ", err)
        print(f"Error text: {response.text}")
        return None

    print(f"All registry for subscription {accountName} have been added successfully")


def get_container_registries(base_url, token):
    url = f"{base_url}/api/v1/settings/registry?project=Central+Console"
    headers = {"content-type": "application/json; charset=UTF-8",
               "Authorization": "Bearer " + token}

    try:
        response = requests.request("GET", url, headers=headers)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except requests.exceptions.RequestException as err:
        print("Oops! An exception occurred in get_container_registries, ", err)
        print(f"Error text: {response.text}")
        return None

    # print(f"Response status code: {response.status_code}")
    # print(f"Response headers: {response.headers}")
    # print(f"Response text: {response.text}")
    return response.json()


def set_cloud_scan_rules(base_url, token, account):
    accountId, accountName = account  # Unpack account tuple

    url = f"{base_url}/api/v1/cloud-scan-rules?project=Central+Console"
    headers = {"content-type": "application/json; charset=UTF-8",
               "Authorization": "Bearer " + token}

    payload = json.dumps([
        {
            "credentialId": f"{accountId}-servicekey",
            "discoveryEnabled": False,
            "agentlessScanSpec": {},
            "serverlessScanSpec": {},
            "awsRegionType": "regular"
        }
    ])

    try:
        response = requests.request("PUT", url, headers=headers, data=payload)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except requests.exceptions.RequestException as err:
        print("Oops! An exception occurred in set_cloud_scan_rules, ", err)
        print(f"Error text: {response.text}")
        return None


def create_cloud_account(base_url, token, account, azure_client_id, azure_client_secret, azure_tenant_id):
    accountId, accountName = account  # Unpack account tuple

    url = f"{base_url}/api/v1/credentials?project=Central+Console"
    headers = {"content-type": "application/json; charset=UTF-8",
               "Authorization": "Bearer " + token}    

    secret_json = json.dumps({
        "clientId": azure_client_id,
        "clientSecret": f"{azure_client_secret}",
        "tenantId": f"{azure_tenant_id}",
        "subscriptionId": f"{accountId}",
        "activeDirectoryEndpointUrl": "https://login.microsoftonline.com",
        "resourceManagerEndpointUrl": "https://management.azure.com/",
        "activeDirectoryGraphResourceId": "https://graph.windows.net/",
        "sqlManagementEndpointUrl": "https://management.core.windows.net:8443/",
        "galleryEndpointUrl": "https://gallery.azure.com/",
        "managementEndpointUrl": "https://management.core.windows.net/"
    })

    payload = json.dumps({
        "caCert": "",
        "secret": {
            "encrypted": "",
            "plain": secret_json
        },
        "apiToken": {
            "encrypted": "",
            "plain": ""
        },
        "description": (f"{accountName}-servicekey")[:30],
        "skipVerify": False,
        "accountID": "",
        "useAWSRole": False,
        "_id": f"{accountId}-servicekey",
        "type": "azure",
        "accountName": f"{accountName}-servicekey",
        "useSTSRegionalEndpoint": False
    })

    try:
        response = requests.request("POST", url, headers=headers, data=payload)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except requests.exceptions.RequestException as err:
        print("Oops! An exception occurred in create_cloud_account, ", err)
        print(f"Error text: {response.text}")
        return None

    # print(f"Response status code: {response.status_code}")
    # print(f"Response headers: {response.headers}")
    # print(f"Response text: {response.text}")
    return response


def get_unique_account_ids(json_data):
    unique_account_ids = set()
    for resource in json_data['resources']:
        account_id = resource['accountId']
        account_name = resource['accountName']
        unique_account_ids.add((account_id, account_name))
    return list(unique_account_ids)


def get_acr(base_url, token):
    url = f"https://{base_url}/resource/scan_info"
    headers = {"content-type": "application/json; charset=UTF-8",
               "x-redlock-auth": token}

    payload = json.dumps({
        "filters": [
            {
                "name": "includeEventForeignEntities",
                "operator": "=",
                "value": "false"
            },
            {
                "name": "cloud.service",
                "operator": "=",
                "value": "Azure Container Registry"
            },
            {
                "name": "cloud.type",
                "operator": "=",
                "value": "azure"
            },
            {
                "name": "resource.type",
                "operator": "=",
                "value": "Azure Container Registry"
            },
            {
                "name": "scan.status",
                "operator": "=",
                "value": "all"
            },
            {
                "name": "decorateWithDerivedRRN",
                "operator": "=",
                "value": False
            }
        ],
        "limit": 100,
        "timeRange": {
            "type": "to_now",
            "value": "epoch"
        }
    })

    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except requests.exceptions.RequestException as err:
        print("Oops! An exception occurred in get_acr, ", err)
        return None

    return response.json()


def read_authorized_subscriptions():
    with open('authorized_sub.conf', 'r') as f:
        subscriptions = [line.strip() for line in f]
    return subscriptions


def read_unauthorized_subscriptions():
    with open('unauthorized_account_name.conf', 'r') as f:
        subscriptions = [line.strip() for line in f]
    return subscriptions


def get_compute_url(base_url, token):
    url = f"https://{base_url}/meta_info"
    headers = {"content-type": "application/json; charset=UTF-8",
               "Authorization": "Bearer " + token}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except requests.exceptions.RequestException as err:
        print("Oops! An exception occurred in get_compute_url, ", err)
        return None

    response_json = response.json()
    return response_json.get('twistlockUrl', None)


def login_saas(base_url, access_key, secret_key):
    url = f"https://{base_url}/login"
    payload = json.dumps({"username": access_key, "password": secret_key})
    headers = {"content-type": "application/json; charset=UTF-8"}
    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except Exception as e:
        print(f"Error in login_saas: {e}")
        return None

    return response.json().get("token")


def login_compute(base_url, access_key, secret_key):
    url = f"{base_url}/api/v1/authenticate"

    payload = json.dumps({
        "username": access_key,
        "password": secret_key
    })
    headers = {"content-type": "application/json; charset=UTF-8"}
    response = requests.post(url, headers=headers, data=payload)
    return response.json()["token"]


def main():
    load_dotenv()
    url = os.environ.get("PRISMA_API_URL")
    identity = os.environ.get("PRISMA_ACCESS_KEY")
    secret = os.environ.get("PRISMA_SECRET_KEY")
    azure_client_id = os.environ.get("AZURE_CLIENT_ID")
    azure_client_secret = os.environ.get("AZURE_CLIENT_SECRET")
    azure_tenant_id = os.environ.get("AZURE_TENANT_ID")

    if not url or not identity or not secret or not azure_client_id or not azure_client_secret or not azure_tenant_id:
        print("Error: PRISMA_API_URL, PRISMA_ACCESS_KEY, PRISMA_SECRET_KEY, AZURE_CLIENT_ID, PRISMA_SECRET_KEY or AZURE_TENANT_ID environment variables are not set.")
        return

    token = login_saas(url, identity, secret)

    if token is None:
        print("Error: Unable to authenticate.")
        return

    compute_url = get_compute_url(url, token)
    compute_token = login_compute(compute_url, identity, secret)
    # print(f"Here is the compute url: {compute_url} and token {compute_token}")

    acr_list = get_acr(url, token)
    # print(f"Here is the acr list: {acr_list}")

    unique_account_ids = get_unique_account_ids(acr_list)
    # print(f"List of azure cloud accounts that contains ACR: {unique_account_ids}")

    authorized_subscriptions = read_authorized_subscriptions()
    unauthorized_subscriptions = read_unauthorized_subscriptions()

    existing_container_registries = get_container_registries(compute_url, compute_token)

    # create a cloud account in the compute part with he service key
    for account in unique_account_ids:
        if not any(sub in account[1] for sub in unauthorized_subscriptions):
            if not authorized_subscriptions or account[0] in authorized_subscriptions:
                create_cloud_account(compute_url, compute_token, account, azure_client_id,
                                     azure_client_secret, azure_tenant_id)
                set_cloud_scan_rules(compute_url, compute_token, account)
                add_container_registries(compute_url, compute_token, existing_container_registries, acr_list, account)
            else:
                print(f"Account {account[0]} is not authorized.")
        else:
            print(f"Account {account[0]} is explicit denied by the configuration.")


if __name__ == "__main__":
    main()
