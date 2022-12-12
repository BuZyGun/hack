from flask import Flask, Response, request
from flask_cors import CORS
import os
import json
import random
import requests as req
from censys.search import CensysHosts
from bs4 import BeautifulSoup as BS
from datetime import datetime


class Censys:
    def __init__(self):
        self.load_config()
        api_id, api_secret = self.load_api_creds()
        os.environ["CENSYS_API_ID"] = api_id
        os.environ["CENSYS_API_SECRET"] = api_secret

        self.engine = CensysHosts()

    def load_config(self):
        if not os.path.exists("config.json"):
            exit()
        with open("config.json") as config_file:
            self.config = json.loads(config_file.read())

    def save_config(self):
        with open("config.json", "w") as config_file:
            config_file.write(json.dumps(self.config, indent=2))

    def load_api_creds(self):
        creds = self.config['creds']
        session_creds = random.choice(creds)
        api_id = session_creds["CENSYS_API_ID"]
        api_secret = session_creds["CENSYS_API_SECRET"]
        return (api_id, api_secret)

    def search(self, ip):
        response = self.engine.search(
            "{}".format(ip)).view_all()
        result = {}
        for host, data in response.items():
            services = [s for s in data['services']
                        if 'certificate' in s.keys()]
            certs = {}
            for s in services:
                s_data = {}
                port = s['port']
                tls = s['tls']
                leaf_data = tls['certificates']['leaf_data']
                s_data['cipher'] = tls['cipher_selected']
                s_data['tls_version'] = tls['version_selected']
                s_data['pubkey_bit_size'] = leaf_data['pubkey_bit_size']
                s_data['self_signed'] = leaf_data['signature']['self_signed']
                s_data['issuer'] = leaf_data['issuer_dn']
                s_data['fingerprint'] = leaf_data['fingerprint']

                cert_data = req.get(
                    'https://search.censys.io/certificates/{}/raw'.format(s_data['fingerprint']))
                if cert_data.status_code == 200:
                    soup = BS(cert_data.text, "html.parser")
                    cert_json = json.loads(str(soup.find('code').getText()))
                    s_data['validity'] = cert_json['parsed']['validity']
                    s_data['validity']['start'] = int(datetime.fromisoformat(
                        s_data['validity']['start']).timestamp())
                    s_data['validity']['end'] = int(datetime.fromisoformat(
                        s_data['validity']['end']).timestamp())

                certs[str(port)] = s_data
            result[str(host)] = certs
        return result


def create_application(engine) -> Flask:
    app = Flask(__name__)
    CORS(app)

    @app.route("/", methods=["GET"])
    def handle_search():
        ip = request.args.get('ip')
        result = engine.search(ip)

        for host, ports_data in result.items():
            for port, data in ports_data.items():
                resp = req.post('http://storage:5002/certs', json={
                    "fingerprint": data['fingerprint'],
                    "tls_version": data['tls_version'],
                    "pubkey_bit_size": data['pubkey_bit_size'],
                    "self_signed": data['self_signed'],
                    "cipher": data['cipher'],
                    "issuer": data['issuer'],
                    "v_start": data['validity']['start'],
                    "v_end": data['validity']['end'],
                    "v_length": data['validity']['length']
                })

                id = req.post('http://storage:5002/hosts', json={
                    "host": host,
                    "port": port,
                    "cert_id": resp.json()['id']
                })
                

        return result

    return app


if __name__ == "__main__":
    c = Censys()
    app = create_application(c)
    app.run(host="0.0.0.0", port=5000, debug=True)
