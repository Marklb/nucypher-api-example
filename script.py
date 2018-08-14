from flask import Flask, abort, jsonify
from flask_cors import CORS

from umbral import config
config.set_default_curve()

from nucypher_api import nucypher_api


app = Flask(__name__)
app.register_blueprint(nucypher_api)
CORS(app)

@app.route('/')
def index():
    return "Hello, World!"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)
