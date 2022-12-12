from flask import Flask, request
from flask_cors import CORS
import requests as req
import os
import json
from datetime import datetime


class Validator:
    def __init__(self):
        self.load_config()
        self.filters = self.config['filters']
        self.weak_ciphers = self.config['weak_ciphers']

    def load_config(self):
        if not os.path.exists("config.json"):
            exit()
        with open("config.json") as config_file:
            self.config = json.loads(config_file.read())
    
    def save_config(self):
        self.config['filters'] = self.filters
        with open("config.json", "w") as config_file:
            config_file.write(json.dumps(self.config, indent=2))

    def validate(self, certs):
        for cert in certs:
            cert['invalid'] = []
            if cert['tls_version'] in self.filters['tls_disallowed']:
                cert['invalid'].append('tls_version')
            if cert['pubkey_bit_size'] < self.filters['key_length']:
                cert['invalid'].append('pubkey_bit_size')
            if cert['cipher'] in self.weak_ciphers and self.filters['warn_weak_ciphers']:
                cert['invalid'].append('cipher')
            if cert['self_signed'] and self.filters["warn_self_signed"]:
                cert['invalid'].append('self_signed')
            if cert['v_end'] < int(datetime.now().timestamp()) and self.filters['check_expired']:
                cert['invalid'].append('fingerprint')
                cert['invalid'].append('v_end')
            if cert['v_end'] < int(datetime.now().timestamp()) + self.filters['expire_in']:
                cert['invalid'].append('fingerprint')
            if cert['v_length'] > self.filters['validity_period']:
                cert['invalid'].append('v_length')
            if len([issuer for issuer in self.filters['issuers'] if issuer in cert['issuer']]) > 0:
                cert['invalid'].append('issuer')
        return certs


        


def create_application(validator) -> Flask:
    app = Flask(__name__)
    CORS(app)

    @app.route("/", methods=['POST', "GET"])
    def certs():
        if request.method == 'GET':
            resp = req.get("http://storage:5002/certs")
            certs = resp.json()
            new_certs = validator.validate(certs)
            return new_certs
        elif request.method == 'POST':
            if request.is_json:
                data = request.get_json()
                validator.filters['check_expired'] = data['check_expired']
                validator.filters['expire_in'] = data['expire_in']
                validator.filters['issuers'] = data['issuers']
                validator.filters['key_length'] = data['key_length']
                validator.filters['tls_disallowed'] = data['tls_disallowed']
                validator.filters['validity_period'] = data['validity_period']
                validator.filters['warn_self_signed'] = data['warn_self_signed']
                validator.filters['warn_weak_ciphers'] = data['warn_weak_ciphers']
                validator.save_config()
            return validator.filters

    @app.route("/filters", methods=['GET'])
    def filters():
        return validator.filters

    return app


if __name__ == "__main__":
    v = Validator()
    app = create_application(v)
    app.run(host="0.0.0.0", port=5001, debug=True)
