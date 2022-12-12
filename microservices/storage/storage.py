from flask import Flask, Response, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects import postgresql
import os

postgresql.CIDR


def create_application() -> Flask:
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://{}:{}@{}:5432/{}'.format(
        os.environ['DB_USER'], os.environ['DB_PASSWORD'], os.environ['DB_HOST'], os.environ['DB_NAME'])
    db = SQLAlchemy(app)

    class CertsModel(db.Model):
        __tablename__ = 'certs'

        id = db.Column(db.Integer, primary_key=True)
        fingerprint = db.Column(db.String)
        tls_version = db.Column(db.String)
        pubkey_bit_size = db.Column(db.Integer)
        self_signed = db.Column(db.Boolean)
        cipher = db.Column(db.String)
        issuer = db.Column(db.String)
        v_start = db.Column(postgresql.BIGINT)
        v_end = db.Column(postgresql.BIGINT)
        v_length = db.Column(postgresql.BIGINT)

        def __init__(self, fingerprint, tls_version, pubkey_bit_size, self_signed, cipher, issuer, v_start, v_end, v_length):
            self.fingerprint = fingerprint
            self.tls_version = tls_version
            self.pubkey_bit_size = pubkey_bit_size
            self.self_signed = self_signed
            self.cipher = cipher
            self.issuer = issuer
            self.v_start = v_start
            self.v_end = v_end
            self.v_length = v_length

        def __repr__(self):
            return f'<Cert {self.fingerprint}>'

    class HostsModel(db.Model):
        __tablename__ = 'hosts'

        id = db.Column(db.Integer, primary_key=True)
        host = db.Column(postgresql.CIDR)
        port = db.Column(db.Integer)
        cert_id = db.Column(db.Integer, db.ForeignKey('certs.id'))
        cert = db.relationship('CertsModel', foreign_keys=cert_id)

        def __init__(self, host, port, cert_id):
            self.host = host
            self.port = port
            self.cert_id = cert_id
            super().__init__()

        def __repr__(self):
            return f'<Host {self.host}>'

    @app.route('/certs', methods=['POST', 'GET'])
    def handle_certs():
        if request.method == 'GET':
            certs = CertsModel.query.all()
            results = [{'fingerprint': cert.fingerprint, 'tls_version': cert.tls_version,
                        'pubkey_bit_size': cert.pubkey_bit_size, 'self_signed': cert.self_signed,
                        'cipher': cert.cipher, 'issuer': cert.issuer, 'v_start': cert.v_start,
                        'v_end': cert.v_end, 'v_length': cert.v_length} for cert in certs]
            return results
        elif request.method == 'POST':
            if request.is_json:
                data = request.get_json()
                new_cert = CertsModel(fingerprint=data['fingerprint'], tls_version=data['tls_version'],
                                      pubkey_bit_size=data['pubkey_bit_size'], self_signed=data['self_signed'],
                                      cipher=data['cipher'], issuer=data['issuer'], v_start=data['v_start'],
                                      v_end=data['v_end'], v_length=data['v_length'])

                if (cert := CertsModel.query.filter(CertsModel.fingerprint == new_cert.fingerprint).first()) != None:
                    return {'id': cert.id}
                else:
                    db.session.add(new_cert)
                    db.session.commit()
                    db.session.refresh(new_cert)
                    return {'id': new_cert.id}
            else:
                return Response('Not a json input')

    @app.route('/hosts', methods=['POST', 'GET'])
    def handle_hosts():
        if request.method == 'GET':
            hosts = HostsModel.query.all()
            results = [{'host': host.host.replace('/32', ''), 'port': host.port,
                        'cert': host.cert.fingerprint} for host in hosts]
            return results
        elif request.method == 'POST':
            if request.is_json:
                data = request.get_json()
                new_host = HostsModel(
                    host=data['host'], port=data['port'], cert_id=data['cert_id'])
                if (host := HostsModel.query.filter(HostsModel.host == new_host.host, HostsModel.port == new_host.port).first()) != None:
                    return {'id': host.id}
                else:
                    db.session.add(new_host)
                    db.session.commit()
                    db.session.refresh(new_host)
                    return {'id': new_host.id}
            else:
                return Response('Not a json input')

    return app


if __name__ == '__main__':
    app = create_application()
    app.run(host='0.0.0.0', port=5002, debug=True)
