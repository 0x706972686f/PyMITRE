import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import json
import logging
import taxii2client
import stix2
import csv

logger = logging.getLogger(__name__)

#PROXIES = {'http': '', 'https': ''}
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
        #session.proxies = PROXIES

        return session


def retrieve_collection(collection_id):
        # Initialize dictionary to hold Enterprise ATT&CK content
        attack = {}

        # Establish TAXII2 Collection instance for Enterprise ATT&CK collection
        collection_url = STIX_URL + "/stix/collections/{}/".format(collection_id)
        collection = taxii2client.Collection(collection_url,verify=False)#,proxies=PROXIES)

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

        return attack

def taxii_feed():
        collection_ids = {}
        server = taxii2client.Server(STIX_URL + "/taxii/",verify=False)#,proxies=PROXIES)
        api_root = server.api_roots[0]
        for collection in api_root.collections:
                collection_ids[collection.title] = collection.id
        return collection_ids


def mitre_group_information(mitre_filter):
        # Create some dictionaries just to store the fields we want
        mitre_id = []
        group_name = []
        for identifier in mitre_filter:
                mitre_id.append(identifier['external_references'][0]['external_id'])
                group_name.append(identifier['name'])

        return mitre_id, group_name

def write_csv_group_and_technique(groupid,groupname,grouptechniques):      
        with open('technique_mappings.csv','a',newline='') as csvfile:
                fieldnames = ['group_id', 'common_name', 'technique_id']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                for technique in grouptechniques:
                        writer.writerow({'group_id': groupid, 'common_name': groupname,'technique_id': technique.get('techniqueID')})    

def get_group_techniques(groups):
        # While the STIX feeds have the technique, they don't have the group to technique mapping, need to rely on the JSON for that.
        #https://attack.mitre.org/groups/G0018/G0018-enterprise-layer.json
        #https://attack.mitre.org/groups/G0026/G0026-enterprise-layer.json
        mitreids, groupnames = mitre_group_information(groups)
        print(mitreids)
        for mid, gid in zip(mitreids,groupnames):
                print(mid, gid)
                session = create_session()
                resp = session.get(url(mid))
                if resp.status_code == 200:
                        techniques = resp.json().get('techniques')
                        write_csv_group_and_technique(mid,gid,techniques)
                else:
                        '''
                        There's a bunch which no longer exist for various reasons, such as oilrig. OilRig (G0049) was previously tracked under two distinct groups, APT34 and OilRig, but was combined due to additional reporting giving higher confidence about the overlap of the activity.

                        APT34 (G0057) has no JSON available, so need to remove it.
                        '''
                        continue
           
def technique_information(techniques):
        tech_dict = {}
        tech_info_dict = {}
        for technique in techniques:
                phase_list = []
                for phase in technique['kill_chain_phases']:
                        phase_list.append(phase['phase_name'])
                tech_info_dict['kill_chain_phases'] = phase_list
                tech_info_dict['name'] = technique['name']
                tech_dict[technique['external_references'][0]['url'].split('/')[-1]] = tech_info_dict

        return tech_dict



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

        mitre_id, group_name = mitre_group_information(attack_model['groups'])
        #technique_dictionary = technique_information(attack_model['techniques'])
        
        #print(dict(zip(mitre_id, group_name)))
        #print(technique_dictionary)
        

        #get_group_techniques(attack_model['groups'])
        

        # For software
        # https://attack.mitre.org/software/S0017/S0017-enterprise-layer.json

        

if __name__ == "__main__":
        start()
