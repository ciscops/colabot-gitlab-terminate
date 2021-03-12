import logging
import json
import datetime
import re
import urllib3
import os

import boto3

FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(format=FORMAT, level=logging.INFO)


class CONFIG:
    K8S_TOKEN = os.environ.get('K8S_TOKEN', 'xxxx')
    K8S_CLUSTER = os.environ.get('K8S_CLUSTER', 'abc12345')
    AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
    AWS_KEY = os.environ.get('AWS_KEY', 'xxxx')
    AWS_SECRET = os.environ.get('AWS_SECRET', 'xxxx')
    AWX_SERVER = os.environ.get('AWX_SERVER', 'xxxx')
    AWX_USERNAME = os.environ.get('AWX_USERNAME', '')
    AWX_PASSWORD = os.environ.get('AWX_PASSWORD', '')
    AWX_TERMINATE_GITLAB_JOB = os.environ.get('AWX_TERMINATE_GITLAB_JOB', '')
    WEBEX_BEARER = os.environ.get('WEBEX_BEARER', '')
    DAYS_BEFORE_WARNINGS = os.environ.get('DAYS_BEFORE_WARNINGS', '7')
    DAYS_OF_WARNINGS = os.environ.get('DAYS_OF_WARNINGS', '7')


def get_k8s_deployments() -> dict:
    server = CONFIG.K8S_CLUSTER
    api = "apis/apps/v1/namespaces/default/deployments/"
    url = server + api
    headers = {"Authorization": f"Bearer {CONFIG.K8S_TOKEN}"}
    try:
        http = urllib3.PoolManager(cert_reqs='CERT_NONE')
        r = http.request(method='GET', url=url, headers=headers)
        deployments = json.loads(r.data.decode('utf-8'))
        return deployments
    except Exception as e:
        logging.error(e)
        return {}


def parse_k8s_deployments_for_colab_gitlab(deployments: dict) -> dict:
    results_dict = dict()
    try:
        for k in deployments['items']:
            if re.search(r'gitlab-.+-gitlab-shell', k['metadata']['name']):
                username = k['metadata']['name'].replace('-gitlab-shell', '')
                username = username.replace('gitlab-', '')
                results_dict[username] = k['metadata']['creationTimestamp']
        return results_dict
    except Exception as e:
        logging.error(e)
        return {}


def get_dynamo_records(table: str) -> list:
    try:
        dynamodb = boto3.resource('dynamodb',
                                  region_name=CONFIG.AWS_REGION)
        table = dynamodb.Table(table)
        response = table.scan()
        items = response['Items']
        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            items.extend(response['Items'])
        return items
    except Exception as e:
        logging.error(e)
        return []


def compare_dynamo_to_k8s_users(dynamo_items: list, k8s_users_ages: dict) -> list:
    stale_dynamo_entries = list()
    for i in dynamo_items:
        if i.get('username') not in k8s_users_ages:
            stale_dynamo_entries.append(i.get('username'))
    return stale_dynamo_entries


def delete_dynamo_entry(table: str, record: str):
    try:
        dynamodb = boto3.resource('dynamodb',
                                  region_name=CONFIG.AWS_REGION)
        table = dynamodb.Table(table)
        table.delete_item(Key={
            'username': record
        })
    except Exception as e:
        logging.error(e)
        logging.error('Error deleting stale dynamodb entry for' + record + ' in table ' + table)


def build_directory() -> dict:
    directory = get_dynamo_records('colab_directory')
    directory_dict = dict()
    try:
        for i in directory:
            directory_dict[i['username']] = i['email']
        return directory_dict
    except Exception as e:
        logging.error(e)
        return {}


def terminate_gitlab(username: str, email: str) -> bool:
    url = f'https://{CONFIG.AWX_SERVER}/api/v2/job_templates/{CONFIG.AWX_TERMINATE_GITLAB_JOB}/launch/'
    headers = urllib3.make_headers(basic_auth=f'{CONFIG.AWX_USERNAME}:{CONFIG.AWX_PASSWORD}')
    headers.update({'Content-Type': 'application/json'})
    body = {"extra_vars": {"colab_user_username": username, "colab_user_email": email}}
    try:
        http = urllib3.PoolManager(cert_reqs='CERT_NONE')
        result = http.request(method='POST', url=url, headers=headers, body=json.dumps(body))

        if result.status == 201:
            logging.info('TERMINATED gitlab workshop for ' + email)
            return True
        else:
            logging.warning('AWX status code to terminate gitlab for ' + email + ': ' + str(result.status_code))
    except Exception as e:
        logging.error(e)
    return False


def send_webex_message(email: str, message: str) -> bool:
    uri = 'https://api.ciscospark.com/v1/messages'
    headers = {
        'Content-Type': 'application/json',
        "Authorization": "Bearer " + CONFIG.WEBEX_BEARER
    }
    body = {
        "toPersonEmail": email,
        "markdown": message,
    }
    try:
        http = urllib3.PoolManager(cert_reqs='CERT_NONE')
        result = http.request(method='POST', url=uri, headers=headers, body=json.dumps(body))
        if result.status == 200:
            return True
        else:
            return False
    except Exception as e:
        print(e)
        return False


def update_dynamo_db(record: dict):
    try:
        dynamodb_client = boto3.client('dynamodb',
                                       region_name=CONFIG.AWS_REGION)
        dynamodb_client.put_item(
            TableName='colab_gitlab',
            Item={
                "username": {"S": f"{record['username']}"},
                "date_renewed": {"S": f"{record['date_renewed']}"},
                "date_renewal_request_sent": {"S": f"{record['date_renewal_request_sent']}"},
                "renewal_request_sent_count": {"S": f"{record['renewal_request_sent_count']}"}
            }
        )
        logging.info("colab-gitlab updated for " + record['username'])
    except Exception as e:
        logging.error(e)
        logging.error('Could not update the dynamo colab_gitlab db.')


def timestamp_to_epoch_time(timestamp: str) -> int:
    deployment_creation_time = datetime.datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')
    return int(deployment_creation_time.timestamp())


def epoch_time_to_timestamp(epoch: int) -> str:
    return datetime.datetime.fromtimestamp(epoch).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_gitlab_users_for_messaging_and_termination(dynamo_items: list):
    directory = build_directory()
    if not directory:
        logging.info('no directory for email lookup. Exiting...')
        return

    for item in dynamo_items:
        now_epoch = int(datetime.datetime.now().timestamp())
        if item['date_renewed']:
            # create epoch time from this
            renewal_epoch = timestamp_to_epoch_time(item['date_renewed'])
        else:
            renewal_epoch = timestamp_to_epoch_time(item['username'])
        if item['date_renewal_request_sent'] != '0':
            renewal_sent_epoch = timestamp_to_epoch_time(item['date_renewal_request_sent'])
        else:
            renewal_sent_epoch = renewal_epoch

        warning_epoch = int(CONFIG.DAYS_BEFORE_WARNINGS) * 24 * 60 * 60
        if now_epoch - renewal_epoch >= warning_epoch and int(
                item['renewal_request_sent_count']) > int(CONFIG.DAYS_OF_WARNINGS):
            if directory.get(item['username']):
                logging.info('Gitlab termination for ' + item['username'])
                if terminate_gitlab(item['username'], directory[item['username']]):
                    message = '**Your cpn-workshops gitlab deployment will be terminated**'
                    send_webex_message(directory[item['username']], message)
            else:
                logging.warning(item['username'] + 'is not in the colab_directory.')
                continue
        elif now_epoch - renewal_epoch >= warning_epoch \
                and renewal_sent_epoch:
            if now_epoch - renewal_sent_epoch >= 86400:
                days = int(CONFIG.DAYS_OF_WARNINGS) - int(item['renewal_request_sent_count'])
                if days != 1:
                    message = f'\n\n**Your cpn-workshops gitlab deployment will be terminated in {str(days)} days!** \n\n  Please use one of the following commands:\n  - ***Extend GitLab*** to extend for another 7 days \n  - ***Terminate GitLab*** command to free cluster resources. \n\n'
                else:
                    message = f'\n\n**Your cpn-workshops gitlab deployment will be terminated in 1 day!** \n\n  Please use one of the following commands:\n  - ***Extend GitLab*** to extend for another 7 days \n  - ***Terminate GitLab*** command to free cluster resources. \n\n'
                if directory.get(item['username']):
                    if send_webex_message(directory[item['username']], message):
                        item['date_renewal_request_sent'] = epoch_time_to_timestamp(now_epoch)
                        item['renewal_request_sent_count'] = str(int(item['renewal_request_sent_count']) + 1)
                        update_dynamo_db(item)


def lambda_handler(event, context):
    k8s_deployments = get_k8s_deployments()
    if not k8s_deployments:
        logging.info('Error connecting to kubernetes cluster...')
        exit(1)
    deployed_gitlabs = parse_k8s_deployments_for_colab_gitlab(k8s_deployments)
    if not deployed_gitlabs:
        logging.info('No labs. Exiting...')
        exit()
    dynamo_gitlab_list = get_dynamo_records(table='colab_gitlab')
    if not dynamo_gitlab_list:
        logging.info('No dynamo list to work with...')
        exit()
    old_dynamo_entries = compare_dynamo_to_k8s_users(dynamo_gitlab_list, deployed_gitlabs)
    print(old_dynamo_entries)

    for entry in old_dynamo_entries:
        delete_dynamo_entry(table='colab_gitlab', record=entry)

    fresh_dynamo_gitlab_list = get_dynamo_records(table='colab_gitlab')
    if not fresh_dynamo_gitlab_list:
        logging.info('No dynamo list to work with...')
        exit()
    parse_gitlab_users_for_messaging_and_termination(fresh_dynamo_gitlab_list)

    return {'statusCode': 200}
