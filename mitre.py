import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import json
import logging
import taxii2client
import stix2

logger = logging.getLogger(__name__)

PROXIES = {'http': 'http://proxy.com:8080', 'https': 'https://proxy.com:8081'}
STIX_URL = "https://cti-taxii.mitre.org"

def hook_response(response, *args, **kwargs):
        try:
                response.raise_for_status()
        except requests.HTTPError as http_err:
                print('HTTP Error occurred: {http_err}')
        except Exception as err:
                print('Other Exception Occurred: {err}')
                logger.debug("Request: {0}\nResponse: {1}".format(response.url, response.json()))

def url(group):
        return "https://attack.mitre.org/groups/{}/{}-enterprise-layer.json".format(group,group)

def create_session():
        headers = {}
        headers['Content-Type'] = 'application/json'

        session = requests.Session()
        session.verify = False
        session.headers = headers
        session.hooks = {'response': hook_response}
        session.proxies = PROXIES

        return session

def print_values(mitre_filter):
        #val = 0
        #for val in range(len(mitre_filter)):
        #        print("ID: {}\n Name: {}\n".format(mitre_filter[val]['id'],mitre_filter[val]['name']))
        return mitre_filter[0]['external_references'][0]['external_id']

        #print(mitre_filter[0])

def retrieve_collection(collection_id):
        # Initialize dictionary to hold Enterprise ATT&CK content
        attack = {}

        # Establish TAXII2 Collection instance for Enterprise ATT&CK collection
        collection_url = STIX_URL + "/stix/collections/{}/".format(collection_id)
        collection = taxii2client.Collection(collection_url,verify=False,proxies=PROXIES)

        # Supply the collection to TAXIICollection
        tc_source = stix2.TAXIICollectionSource(collection)

        # Create filters to retrieve content from Enterprise ATT&CK based on type
        taxii_filters = {
                "techniques": stix2.Filter("type", "=", "attack-pattern"),
                "mitigations": stix2.Filter("type", "=", "course-of-action"),
                "groups": stix2.Filter("type", "=", "intrusion-set"),
                "malware": stix2.Filter("type", "=", "malware"),
                "tools": stix2.Filter("type", "=", "tool"),
                "relationships": stix2.Filter("type", "=", "relationship"),
                "tactic": stix2.Filter("type","=","x-mitre-tactic"),
                "matrix": stix2.Filter("type","=","x-mitre-matrix")
        }

        # Retrieve all Enterprise ATT&CK content
        for field in taxii_filters:
                attack[field] = tc_source.query(taxii_filters[field])

        # For visual purposes, print the first technique received from the server
        # print(attack["techniques"][0])
        return attack

def taxii_feed():
        collection_ids = {}
        server = taxii2client.Server(STIX_URL + "/taxii/",verify=False,proxies=PROXIES)
        api_root = server.api_roots[0]
        for collection in api_root.collections:
                collection_ids[collection.title] = collection.id
        return collection_ids

def start():
        taxii_collection = taxii_feed()
        '''
        Possible Collections that are in MITRE's TAXII feed currently:
        Enterprise ATT&CK: 95ecc380-afe9-11e4-9b6c-751b66dd541e
        PRE-ATT&CK: 062767bd-02d2-4b72-84ba-56caef0f8658
        Mobile ATT&CK: 2f669986-b40b-4423-b720-4396ca6a462b

        Only looking at Enterprise ATT&CK at the moment
        '''                  
        attack_model = retrieve_collection(taxii_collection['Enterprise ATT&CK'])
        test_values = print_values(attack_model['groups'])
        print(attack_model['groups'][0])

        session = create_session()
        resp = session.get(url(test_values)).json()
        print(resp)

        # An example:
        # https://attack.mitre.org/groups/G0018/G0018-enterprise-layer.json


if __name__ == "__main__":
        start()