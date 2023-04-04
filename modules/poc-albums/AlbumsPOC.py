import json
import sys
import multiprocessing
import datetime
import requests
import pandas as pd
from flask import Flask, redirect, request
from werkzeug import run_simple

# TODO obtain from file: toml/yaml/json/env
KHEOPS_ROOT_URL = "http://127.0.0.1"
KHEOPS_API_PATH = "/api"
KHEOPS_API_URL = "http://127.0.0.1/api"
KHEOPS_OIDC_PROVIDER = "http://127.0.0.1:8080/auth/realms/kheops"
OIDC_PROTOCOL = '/protocol/openid-connect'
OIDC_REQUEST_PARAMETERS = "&client_id=loginConnect&redirect_uri=http://localhost:8089/code"

def get_token_webserver(mpqueue, host, port):

    app = Flask(__name__)

    @app.route("/")
    def start():
        return redirect(KHEOPS_OIDC_PROVIDER + OIDC_PROTOCOL + '/auth?response_type=code' + OIDC_REQUEST_PARAMETERS)

    @app.route("/code")
    def code_handler():
        # TODO verify code, authorization_code request succeed
        # consider using dedicated library such as 'oidc-client'
        payload = f'code={request.args.get("code")}&grant_type=authorization_code' + OIDC_REQUEST_PARAMETERS
        r = requests.post(KHEOPS_OIDC_PROVIDER + OIDC_PROTOCOL + '/token',
                            headers={'Content-Type': 'application/x-www-form-urlencoded'},
                            data=payload)
        json = r.json()
        mpqueue.put(json)
        print("Token granted")
        return "Success! Return to console"
    
    run_simple(host, port, app)

def get_token_from_user():
    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=get_token_webserver, args=(q,'0.0.0.0',8089))
    p.start()
    print("Navigate to http://localhost:8089/ and login to KHEOPS to proceed.")
    token_json = q.get(block=True)
    p.terminate()
    return token_json

def extract_studyInstanceUID_from_csv(fname):
    df = pd.read_csv(fname)
    return df['StudyInstanceUID'].to_list()

class KheopsAPIConnector:

    def __init__(self, token_json):
        self._token_json = token_json
        self.access_token = token_json['access_token']
        self.refresh_token = token_json['refresh_token']

    def _request_with_bearer_token():
        """ TODO handle adding auth token, refresh token here """
        pass

    def get_study_list(self, bearer_token):
        r = requests.get(KHEOPS_API_URL + '/studies', headers={'Authorization': f'Bearer {self.access_token}'})
        studies = json.loads(r.text) # r.json() doesn't work because Content-Type is application/dicom+json
        return studies

    def create_album(self, studies, album_details):
        r = requests.post(KHEOPS_API_URL + '/albums', data=album_details, headers={'Authorization': f'Bearer {self.access_token}'})
        json = r.json()
        for StudyInstanceUID in studies:
            r = requests.put(KHEOPS_API_URL + f'/studies/{StudyInstanceUID}/albums/{json["album_id"]}?inbox=true', headers={'Authorization': f'Bearer {self.access_token}'})
            print(r.text)
        return json

    def create_public_album_link(self, album_id, album_sharing_params):
        album_sharing_params |= {
            'title': 'sharing_link',
            'scope_type': 'album',
            'album': album_id
        }
        r = requests.post(KHEOPS_API_URL + '/capabilities', data=album_sharing_params, headers={'Authorization': f'Bearer {self.access_token}'})
        json = r.json()
        print(json)
        #return "Hey"
        return f'{KHEOPS_ROOT_URL}/view/{json["access_token"]}'

if __name__ == "__main__":
    token_json = get_token_from_user()
    #print(json.dumps(token_json, indent=2))
    kheops = KheopsAPIConnector(token_json)
    
    # print("Getting study list")
    # print(json.dumps(kheops.study_list(token_json['access_token']), indent=2))
    studies = extract_studyInstanceUID_from_csv('cfind-output.csv')
    album = kheops.create_album(studies, {
        'name': 'Test Album',
        'description': 'This is a test album',
        'addSeries': 'false',
        'downloadSeries': 'true'
    })
    print("Album \"%s\" created: %s" % (album['name'], album['album_id']))
    valid_until = datetime.datetime.utcnow() + datetime.timedelta(days=30)
    public_album_link = kheops.create_public_album_link(album['album_id'], {
        'read_permission': 'true',
        'write_permission': 'false',
        'download_permission': 'true',
        'appropriate_permission': 'true',
        'expiration_time': valid_until.strftime('%Y-%m-%dT%H:%M:%S-00:00')
    })
    print("Public album link: {}".format(public_album_link))
    print("Valid until: {}".format(valid_until.strftime('%Y-%m-%dT%H:%M:%S-00:00')))
