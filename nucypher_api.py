import base64
import json
import maya
import datetime

from flask import Flask, abort, jsonify, Blueprint, request
from flask_cors import CORS
import sqlite3

from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from nucypher.crypto.kits import UmbralMessageKit

from api import Api


api = Api(node_meta_dir = "../nucypher/examples/examples-runtime-cruft")

nucypher_api = Blueprint('nucypher_api', __name__)
CORS(nucypher_api)

route_prefix = '/api/v' + Api.VERSION

@nucypher_api.route(f'{route_prefix}/gen_keypair', methods=['GET'])
def gen_keypair():
    """
    Generate a keypair using Umbral

    NOTE: This may be removed in favor of a client lib for generating keys

    Response is a dict containing `public_key` and `private_key` bytes encoded as
    base64.urlsafe_b64encode utf-8 string

    response:
        {
            "success": "",
            "keypair": {
                "private_key": "",
                "public_key": "",
            }
            "err_msg": ""
        }
    """
    result = {
        'success': False,
        'keypair': None,
        'err_msg': None
    }

    try:
        # Generate keypair
        private_key, public_key = api.gen_keypair()

        # Format the response
        result['keypair'] = {
            'private_key': private_key.to_bytes(encoder=base64.urlsafe_b64encode).decode('utf8'),
            'public_key': public_key.to_bytes(encoder=base64.urlsafe_b64encode).decode('utf8')
        }

        result['success'] = True
    except Exception as e:
        result['success'] = False
        result['err_msg'] = str(e)

    # Create response
    response = jsonify(result)
    return response

@nucypher_api.route(f'{route_prefix}/create_policy', methods=['POST'])
def create_policy():
    """
    input:
        {
            "label": "",-
            "alice_privkey": "",
            "bob_pubkey": "",
            "policy_expiration": "",
            "m": "",
            "n": ""
        }

    response:
        {
            "success": "",
            "policy_pubkey": "",
            "policy_expiration_date": "",
            "err_msg": ""
        }
    """
    result = {
        'success': False,
        'policy_pubkey': None,
        'policy_expiration_date': None,
        'err_msg': None
    }

    try:
        j = json.loads(request.data.decode('utf-8'))

        # TODO: Check if the input is valid

        # Parse the input values
        label = j['label'].encode('utf-8')
        alice_privkey = UmbralPrivateKey.from_bytes(j['alice_privkey'], decoder=base64.urlsafe_b64decode)
        bob_pubkey = UmbralPublicKey.from_bytes(j['bob_pubkey'], decoder=base64.urlsafe_b64decode)
        policy_expiration = maya.now() + datetime.timedelta(days=int(j['policy_expiration']))
        m = int(j['m'])
        n = int(j['n'])

        # Create the policy
        policy = api.create_policy(label, alice_privkey, bob_pubkey,
            policy_expiration, m, n)

        # Format the response
        result['policy_pubkey'] = base64.urlsafe_b64encode(policy.public_key.to_bytes()).decode('utf8')
        result['policy_expiration_date'] = str(policy_expiration)

        result['success'] = True
    except Exception as e:
        result['success'] = False
        result['err_msg'] = str(e)

    # Create response
    response = jsonify(result)
    return response

@nucypher_api.route(f'{route_prefix}/revoke_policy', methods=['POST'])
def revoke_policy():
    """
    NOTE: This custom revoke hack is not working in the current nucypher version

    input:
        {
            "label": "",
            "alice_privkey": "",
            "bob_pubkey": ""
        }

    response:
        {
            "success": "",
            "err_msg": ""
        }
    """
    result = {
        'success': False,
        'err_msg': None
    }

    try:
        j = json.loads(request.data.decode('utf-8'))

        # TODO: Check if the input is valid

        # Parse the input values
        label = j['label'].encode('utf-8')
        alice_privkey = UmbralPrivateKey.from_bytes(j['alice_privkey'], decoder=base64.urlsafe_b64decode)
        bob_pubkey = UmbralPublicKey.from_bytes(j['bob_pubkey'], decoder=base64.urlsafe_b64decode)

        # Revoke the policy
        policy = api.revoke_policy(label, alice_privkey, bob_pubkey)

        # Format the response

        result['success'] = True
    except Exception as e:
        result['success'] = False
        result['err_msg'] = str(e)

    # Create response
    response = jsonify(result)
    return response

@nucypher_api.route(f'{route_prefix}/encrypt_for_policy', methods=['POST'])
def encrypt_for_policy():
    """
    Create a Policy with Alice granting Bob access to `label` DataSource

    input:
        {
            "policy_pubkey": "",
            "plaintext": ""
        }

    response:
        {
            "success": "",
            "data_source_pubkey": "",
            "message_kit": "",
            "message_kit_signature": "",
            "err_msg": ""
        }
    """
    result = {
        'success': False,
        'data_source_pubkey': None,
        'message_kit': None,
        'message_kit_signature': None,
        'err_msg': None
    }

    try:
        j = json.loads(request.data.decode('utf-8'))

        # TODO: Check if the input is valid

        # Parse the input values
        policy_pubkey = UmbralPublicKey.from_bytes(j['policy_pubkey'], decoder=base64.urlsafe_b64decode)
        plaintext = base64.b64decode(j['plaintext'])

        # Encrypt plaintext for policy
        data_source, message_kit, _signature = api.encrypt_for_policy(policy_pubkey, plaintext)

        # Format the response data
        result['data_source_pubkey'] = base64.urlsafe_b64encode(bytes(data_source.stamp)).decode('utf8')
        result['message_kit'] = base64.urlsafe_b64encode(message_kit.to_bytes()).decode('utf8')
        result['message_kit_signature'] = base64.urlsafe_b64encode(bytes(_signature)).decode('utf8')

        result['success'] = True
    except Exception as e:
        result['success'] = False
        result['err_msg'] = str(e)

    # Create response
    response = jsonify(result)
    return response

@nucypher_api.route(f'{route_prefix}/decrypt_for_policy', methods=['POST'])
def decrypt_for_policy():
    """
    input:
        {
            "label": "",
            "message_kit": "",
            "alice_pubkey": "",
            "bob_privkey": "",
            "policy_pubkey": "",
            "data_source_pubkey": ""
        }

    response:
        {
            "success": "",
            "cleartext": "",
            "err_msg": ""
        }
    """
    result = {
        'success': False,
        'cleartext': None,
        'err_msg': None
    }

    try:
        j = json.loads(request.data.decode('utf-8'))

        # TODO: Check if the input is valid

        # Parse the input values
        label = j['label'].encode('utf-8')
        message_kit = UmbralMessageKit.from_bytes(base64.urlsafe_b64decode(j['message_kit']))
        alice_pubkey = UmbralPublicKey.from_bytes(j['alice_pubkey'], decoder=base64.urlsafe_b64decode)
        bob_privkey = UmbralPrivateKey.from_bytes(j['bob_privkey'], decoder=base64.urlsafe_b64decode)
        policy_pubkey = UmbralPublicKey.from_bytes(j['policy_pubkey'], decoder=base64.urlsafe_b64decode)
        data_source_pubkey = UmbralPublicKey.from_bytes(j['data_source_pubkey'], decoder=base64.urlsafe_b64decode)

        # Encrypt plaintext for policy
        cleartext = api.decrypt_for_policy(label, message_kit, alice_pubkey,
            bob_privkey, policy_pubkey, data_source_pubkey)

        # Format the response data
        result['cleartext'] = base64.urlsafe_b64encode(cleartext).decode('utf8')

        result['success'] = True
    except Exception as e:
        result['success'] = False
        result['err_msg'] = str(e)

    # Create response
    response = jsonify(result)
    return response
