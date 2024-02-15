import requests
import json
import pandas as pd
from datetime import datetime

API_KEY = '82a923a5-628e-4941-8f2d-739644d26ae7'
GR_API_ENDPOINT = 'https://api.guardrails.io/v2/'
PROVIDER = 'github'  # (github, gitlab, bitbucket, azure)
CURRENT_TIME = datetime.now()

# Exchange API Key for JWT
headers = {
    "Content-Type": "application/json"
}
payload = {
    "apiKey": API_KEY
}

try:
    response = requests.post(url=f'{GR_API_ENDPOINT}/auth', headers=headers, data=json.dumps(payload))
    response.raise_for_status()
    accounts_info = response.json()
except requests.exceptions.RequestException as e:
    print("An error occurred:", str(e))

response_json = response.json()
JWT = response_json["jwtToken"]

# Header including JWT for all API requests
headers = {
    "Authorization": "bearer " + JWT
}

# Accounts (Organizations)
try:
    response = requests.get(url=f'{GR_API_ENDPOINT}/accounts', headers=headers)
    response.raise_for_status()
    accounts_info = response.json()
except requests.exceptions.RequestException as e:
    print("An error occurred:", str(e))

print("### List of Organizations ###")
for account in accounts_info[f"{PROVIDER}"]:
    print(f'{account["idAccount"]} - {account["login"]}')
selected_accountId = input("Please select AccountId: ")
for account in accounts_info[f"{PROVIDER}"]:
    if account['idAccount'] == int(selected_accountId):
        global selected_accountName
        selected_accountName = account['login']

# Repos
try:
    response = requests.get(url=f"{GR_API_ENDPOINT}/repositories?accountId={selected_accountId}", headers=headers)
    response.raise_for_status()
    repos_info = response.json()
except requests.exceptions.RequestException as e:
    print("An error occurred:", str(e))

print("### List of Repositories ###")
for repo in repos_info['repositories']:
    print(f'{repo["idRepository"]} - {repo["name"]}')
selected_repoId = input("Please select RepositoryId: ")
for repo in repos_info['repositories']:
    if repo['idRepository'] == int(selected_repoId):
        global selected_repoName
        selected_repoName = repo['name']

# Rules
try:
    response = requests.get(url=f'{GR_API_ENDPOINT}/findings?accountId={selected_accountId}&repositoryIds={selected_repoId}', headers=headers)
    response.raise_for_status()
    rules_info = response.json()
except requests.exceptions.RequestException as e:
    print("An error occurred:", str(e))

rulesId_list = [rule["rule"]["idRule"] for rule in rules_info['data']]
rulesTitle_list = [rule["rule"]["title"] for rule in rules_info['data']]
rulesVul_list = [rule["count"]["total"] for rule in rules_info['data']]

# Vulnerabilities
data = pd.DataFrame()
for ruleId in rulesId_list:
    try:
        response = requests.get(url=f'{GR_API_ENDPOINT}/findings/{ruleId}?accountId={selected_accountId}&repositoryIds={selected_repoId}', headers=headers)
        response.raise_for_status()
        vulns_info = response.json()
    except requests.exceptions.RequestException as e:
        print("An error occurred:", str(e))
    data = data._append(pd.DataFrame(vulns_info), ignore_index=True)

data.to_csv(f"{selected_accountName}_{selected_repoName}_{CURRENT_TIME}.csv")
