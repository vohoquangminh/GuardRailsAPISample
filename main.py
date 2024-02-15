import requests
import json
import pandas as pd
from datetime import datetime

API_KEY = ''  # Generate your API_KEY in the GuardRails Dashboard
GR_API_ENDPOINT = 'https://api.guardrails.io/v2/'
PROVIDER = 'github'  # Input your Git Provider information (github, gitlab, bitbucket, azure)
CURRENT_TIME = datetime.now()

# Exchange API Key for JWT
headers = {
    'Content-Type': 'application/json'
}
payload = {
    'apiKey': API_KEY
}

try:
    response = requests.post(url=f'{GR_API_ENDPOINT}/auth', headers=headers, data=json.dumps(payload))
    response.raise_for_status()
    response_json = response.json()
    JWT = response_json['jwtToken']
except requests.exceptions.RequestException as e:
    print('An error occurred:', str(e))
    exit()

# Header including JWT for all API requests
headers = {
    'Authorization': 'bearer ' + JWT
}


# Function to handle API requests
def make_api_request(url, params=None):
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print('An error occurred:', str(e))
        return None


# Accounts (Organizations)
accounts_info = make_api_request(f'{GR_API_ENDPOINT}/accounts')
if not accounts_info:
    exit()

print('### List of Organizations ###')
for account in accounts_info[f'{PROVIDER}']:
    print(f'{account["idAccount"]} - {account["login"]}')
selected_accountId = input('Please select AccountId: ')
selected_accountName = next(
    (account['login'] for account in accounts_info[f'{PROVIDER}'] if account['idAccount'] == int(selected_accountId)),
    None)

# Repos
repos_info = make_api_request(f'{GR_API_ENDPOINT}/repositories?accountId={selected_accountId}')
if not repos_info:
    exit()

print('### List of Repositories ###')
for repo in repos_info['repositories']:
    print(f'{repo["idRepository"]} - {repo["name"]}')
selected_repoId = input('Please select RepositoryId: ')
selected_repoName = next(
    (repo['name'] for repo in repos_info['repositories'] if repo['idRepository'] == int(selected_repoId)), None)

# Rules
rules_info = make_api_request(
    f'{GR_API_ENDPOINT}/findings?accountId={selected_accountId}&repositoryIds={selected_repoId}')
if not rules_info:
    exit()

rulesId_list = [rule['rule']['idRule'] for rule in rules_info['data']]
rulesTitle_list = [rule['rule']['title'] for rule in rules_info['data']]
rulesVul_list = [rule['count']['total'] for rule in rules_info['data']]

# Vulnerabilities
data = pd.DataFrame()
for ruleId in rulesId_list:
    vulns_info = make_api_request(
        f'{GR_API_ENDPOINT}/findings/{ruleId}?accountId={selected_accountId}&repositoryIds={selected_repoId}')
    if vulns_info:
        data = data._append(pd.DataFrame(vulns_info), ignore_index=True)

data.to_csv(f'{selected_accountName}_{selected_repoName}_{CURRENT_TIME}.csv')
