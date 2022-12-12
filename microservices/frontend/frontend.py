from flask import Flask, Response, render_template
import requests as req
from datetime import datetime


def create_application() -> Flask:
    app = Flask(__name__)
    context = {
        'fromtimestamp': datetime.fromtimestamp,
        'strftime': datetime.strftime,
        'requests': req}

    @app.route("/", methods=["GET"])
    def certs():
        resp = req.get("http://validator:5001/")
        return render_template('certs.html', certs=resp.json(), **context)

    @app.route("/hosts", methods=["GET"])
    def hosts():
        resp = req.get("http://storage:5002/hosts")
        return render_template('hosts.html', hosts=resp.json(), **context)

    @app.route("/scan", methods=["GET"])
    def scan():
        return render_template('scan.html', **context)

    @app.route("/config", methods=["GET"])
    def config():
        return render_template('config.html', **context)

    return app


if __name__ == "__main__":
    app = create_application()
    app.run(host="0.0.0.0", port=80, debug=True)
