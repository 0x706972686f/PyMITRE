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

def api_url(jira_ticket=None,issueType=None):
    if jira_ticket:
        return JIRA_URL + 'rest/api/2/issue/' + jira_ticket
    elif issueType:
        return JIRA_URL + '/rest/api/2/issueLinkeType/' + issueType
    else:
        return JIRA_URL + 'rest/api/2/issue/'

def create_tickets(sess, jira_ticket_summary):
    project = {}
    project_fields = {}

    project_fields['project'] = {'key': 'PROJKEY'}
    project_fields['summary'] = jira_ticket_summary
    project_fields['description'] = 'Insert Description Here'
    project_fields['issuetype'] = {'name': 'Story'}

    project['fields'] = project_fields
    r = sess.post(api_url(), data=json.dumps(project))

    result = r.json()

    return result['key']

def update_tickets(sess, detection_ticket, next_steps_ticket):
    update = {}
    update_fields = {}

    ''' The linking is a custom type, so you'll need to use an existing connection, or create one and query the API to find the ID of it'''
    update_fields['add'] = {'type': {'id': '1000', 'name': 'Connection Name', 'inward': 'Connects to', 'outward': 'connects from', 'self': api_url(issueType='1000')}, 'inwardIssue': {'key': detection_ticket}}
    update['update'] = {'issuelinks': [update_fields]}

    r = sess.put(api_url(jira_ticket=next_steps_ticket), data=json.dumps(update))

def read_csv():
    content = []
    with open('tickets_to_be_linked.csv', encoding='utf-8-sig', newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            content.append(row)
    return content

def start():
    '''
    Given a CSV file which consists of two fields, the first being the ticket ID of the Jira Case that represents some detection 
    (known as the detection_ticket), and a summary of that ticket, will go and create another ticket that represents the
    actions to be taken for an analyst based on a detection (known as the next_steps_ticket), and then will link the two together.
    '''
    content = read_csv()

    sess = authorised_session()

    for row in content:
        detect_ticket = row[0]
        summary = row[-1]
        next_steps_ticket = create_tickets(sess,summary)
        update_tickets(sess, detect_ticket, next_steps_ticket)
        print(detect_ticket + ' links to ' + next_steps_ticket)

if __name__ == "__main__":
    start()