import requests
import json
import sys
import csv
import getpass

requests.packages.urllib3.disable_warnings()

JIRA_URL = 'https://jira.domain/'

def create_session():
    session = requests.Session()
    session.verify=False
    session.headers = {'Content-Type': 'application/json'}
    session.hooks = {'response': hook_response}
    return session

def authorised_session():
    USER = getpass.getuser()
    PASSWORD = getpass.getpass('JIRA Password: ')
    session = create_session()
    session.auth = (USER, PASSWORD)
    return session

def hook_response(r, *args, **kwargs):
    r.raise_for_status()

def api_url(jira_ticket=None):
    if jira_ticket:
        return JIRA_URL + 'rest/api/2/issue/' + jira_ticket
    else:
        return JIRA_URL + 'rest/api/2/issue/'

def add_label_to_ticket(input_list):
    jira_ticket = input_list[0]
    jira_label = input_list[1]

    print('Current Updating JIRA Ticket: ' + jira_ticket)
    labels_to_add = []
    for label in jira_label.split():
            labels_to_add.append({'add': label})
    
    sess = authorised_session()

    post_data = {}
    post_data['update'] = {"labels": labels_to_add}

    r = sess.put(api_url(jira_ticket), data=json.dumps(post_data))
    
def read_csv():
    content = []
    with open('tickets_to_be_linked.csv', encoding='utf-8-sig', newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            content.append(row)
    return content

def start():
    '''
    Given a CSV file which consists of two fields, the first being the ticket ID of the Jira Case that represents the ticket to be 
    updated, and the second being the labels to add to that ticket. This code will then go and update all of those tickets with that
    label.
    
    The objective of this was to label jira tickets with mitre techniques.
    '''
    content = read_csv()

    sess = authorised_session()

    for row in content:
        add_label_to_ticket(row)

if __name__ == "__main__":
    start()