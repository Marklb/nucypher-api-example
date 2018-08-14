###################################
# TEMPORARILY disabling.
# Probably shouldn't do this, but I wanted to stop the spam and not spend time 
#   figuring this out yet.
import urllib3
urllib3.disable_warnings()
###################################

import binascii
import datetime
import sys

from nucypher.characters import Alice, Bob, Ursula
from nucypher.data_sources import DataSource
from nucypher.network.middleware import RestMiddleware
from nucypher.crypto.powers import SigningPower, KeyPairBasedPower, DerivedKeyBasedPower, EncryptingPower, DelegatingPower
from nucypher.crypto.kits import UmbralMessageKit
from nucypher.keystore.keypairs import Keypair, SigningKeypair, EncryptingKeypair
from nucypher.crypto.api import keccak_digest
from nucypher.network.server import ProxyRESTServer
from nucypher.keystore.threading import ThreadedSession
from nucypher.keystore.db.models import Key, PolicyArrangement, Workorder
import maya

from umbral import pre, keys, config, fragments
from umbral.keys import UmbralPrivateKey, UmbralPublicKey, UmbralKeyingMaterial

import base64

from nucypher.crypto.utils import fingerprint_from_key

class Api(object):
    """
    Simplified api for using nucypher.

    Some of the methods are not named correctly if thinking about nucypher,
    instead they are simplified to terms that relate to the terms currently in
    the AgriBlockchainApp.

    NOTE: Only meant to assist with providing a rest api for AgriBlockchainApp
    development.
    """
    VERSION = '3.0'

    # TODO: Don't use 1 for `m` and `n`
    DEFAULT_M = 1
    DEFAULT_N = 1

    DEFAULT_POLICY_EXPIRATION = maya.now() + datetime.timedelta(days=365)

    def __init__(self, teacher_dht_port: int = 3500, teacher_rest_port: int = 3600, 
        node_meta_dir: str = "../examples/examples-runtime-cruft"):
        self.teacher_dht_port = teacher_dht_port

        if teacher_rest_port:
            self.teacher_rest_port = teacher_rest_port
        else:
            self.teacher_rest_port = int(self.teacher_dht_port) + 100

        with open("{}/node-metadata-{}".format(node_meta_dir, self.teacher_rest_port), "r") as f:
            f.seek(0)
            teacher_bytes = binascii.unhexlify(f.read())

        self.ursula = Ursula.from_bytes(teacher_bytes, federated_only=True)

    def gen_keypair(self):
        """
        Generate a keypair using Umbral

        :return: private_key, public_key
        """
        private_key = keys.UmbralPrivateKey.gen_key()
        public_key = private_key.get_pubkey()
        return private_key, public_key

    def create_policy(self, label: bytes, alice_privkey: UmbralPrivateKey, 
        bob_pubkey: UmbralPublicKey, policy_expiration, m: int, n: int):
        """
        Create a Policy with Alice granting Bob access to `label` DataSource

        :param label: A label to represent the policies data
        :param alice_privkey: Alice's private key
        :param bob_pubkey: Bob's public key
        :param policy_expiration: Datetime of policy expiration duration
        :param m: Minimum number of KFrags needed to rebuild ciphertext
        :param n: Total number of rekey shares to generate

        :return: The policy granted to Bob
        """
        # This is not how this should be implemented, but I am still figuring out
        # the keying material and why it is randomly generated when a character is
        # initialized, instead of being derived from the keys like the other powers
        # or explained how it should be stored.
        d = DelegatingPower()
        d.umbral_keying_material = UmbralKeyingMaterial.from_bytes(alice_privkey.to_bytes() + alice_privkey.get_pubkey().to_bytes())

        # Initialize Alice
        ALICE = Alice(
            crypto_power_ups=[
                SigningPower(keypair=SigningKeypair(alice_privkey)),
                EncryptingPower(keypair=EncryptingKeypair(alice_privkey)),
                # DelegatingPower
                d
            ], 
            network_middleware=RestMiddleware(),
            known_nodes=(self.ursula,),
            federated_only=True,
            always_be_learning=True
        )

        # Initialize Bob
        BOB = Bob(
            crypto_power_ups=[
                SigningPower(pubkey=bob_pubkey),
                EncryptingPower(pubkey=bob_pubkey)
            ],
            known_nodes=(self.ursula,),
            federated_only=True,
            always_be_learning=True
        )

        # Alice grants a policy for Bob
        policy = ALICE.grant(BOB, label, m=m, n=n, expiration=policy_expiration)

        return policy

    def revoke_policy(self, label, alice_privkey: UmbralPrivateKey, 
        bob_pubkey: UmbralPublicKey):
        """
        TODO: Figure out the correct way to revoke instead of using a custom
            implementation

        Revoke a Policy that Alice granted Bob to access `label` DataSource

        :param label: A label to represent the policies data
        :param alice_privkey: Alice's private key
        :param bob_pubkey: Bob's public key
        """
        # TODO: Figure out a way to allow revoking with the new way arrangements 
        #   are stored.

        # NOTE: Not working anymore
        # alice_pubkey = alice_privkey.get_pubkey()
        # hrac = keccak_digest(bytes(alice_pubkey) + bytes(bob_pubkey) + label)

        # db_name = 'non-mining-proxy-node'
        # test_server = ProxyRESTServer('localhost', 3601, db_name)
        # test_server.start_datastore(db_name)

        # with ThreadedSession(test_server.db_engine) as session:
        #     test_server.datastore.del_policy_arrangement(
        #         hrac=hrac.hex().encode(),
        #         session=session
        #     )

    def encrypt_for_policy(self, policy_pubkey: UmbralPublicKey, plaintext: bytes):
        """
        Encrypt data for a Policy

        :param policy_pubkey: Policy public key
        :param plaintext: Plaintext bytes to encrypt

        :return: data_source, message_kit, _signature
        """
        # First we make a DataSource for this policy
        data_source = DataSource(policy_pubkey_enc=policy_pubkey)

        # Generate a MessageKit for the policy
        message_kit, _signature = data_source.encapsulate_single_message(plaintext)

        return data_source, message_kit, _signature

    def decrypt_for_policy(self, label: bytes, message_kit: UmbralMessageKit, 
        alice_pubkey: UmbralPublicKey, bob_privkey: UmbralPrivateKey,
        policy_pubkey: UmbralPublicKey, data_source_pubkey: UmbralPublicKey):
        """
        Decrypt data for a Policy

        :param label: A label to represent the policies data
        :param message_kit: UmbralMessageKit
        :param alice_pubkey: Alice's public key
        :param bob_privkey: Bob's private key
        :param policy_pubkey: Policy's private key
        :param data_source_pubkey: DataSource's private key

        :return: The decrypted cleartext
        """
        print('decrypt_for_policy')
        # Initialize Bob
        BOB = Bob(
            crypto_power_ups=[
                SigningPower(keypair=SigningKeypair(bob_privkey)),
                EncryptingPower(keypair=EncryptingKeypair(bob_privkey))
            ],
            known_nodes=(self.ursula,),
            federated_only=True,
            always_be_learning=True
        )
        print('-=-=-=')
        print(label)
        print(bytes(alice_pubkey))
        # Bob joins the policy so that he can receive data shared on it
        BOB.join_policy(label,  # The label - he needs to know what data he's after.
                        bytes(alice_pubkey),  # To verify the signature, he'll need Alice's public key.
                        # verify_sig=True,  # And yes, he usually wants to verify that signature.
                        # He can also bootstrap himself onto the network more quickly
                        # by providing a list of known nodes at this time.
                        node_list=[("localhost", 3601)]
                        )
        print('-=-=-=2')
        # Bob needs to reconstruct the DataSource.
        datasource_as_understood_by_bob = DataSource.from_public_keys(
            policy_public_key=policy_pubkey,
            datasource_public_key=bytes(data_source_pubkey),
            label=label
        )
        print('-=-=-=3')
        # NOTE: Not sure if I am doing something wrong or if this is missing
        #   from the serialized bytes
        message_kit.policy_pubkey = policy_pubkey

        # Now Bob can retrieve the original message.  He just needs the MessageKit
        # and the DataSource which produced it.
        cleartexts = BOB.retrieve(message_kit=message_kit,
                                data_source=datasource_as_understood_by_bob,
                                alice_verifying_key=alice_pubkey)
        print('-=-=-=4')
        return cleartexts[0]

