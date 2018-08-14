import datetime
import maya
import base64

from umbral.keys import UmbralPrivateKey, UmbralPublicKey

from api import Api

policy_expiration = maya.now() + datetime.timedelta(days=365)
m = 1
n = 1

api = Api(node_meta_dir = '../examples/examples-runtime-cruft')

# private_key1, public_key1 = api.gen_keypair()
# private_key2, public_key2 = api.gen_keypair()

private_key1 = UmbralPrivateKey.from_bytes('DGgxOtqZOrqY-lh_E_L5H2YpNBoT3HEW6whMcVcqf5c=', decoder=base64.urlsafe_b64decode)
public_key1 = private_key1.get_pubkey()
print(bytes(public_key1))

private_key2 = UmbralPrivateKey.from_bytes('8886EWu9cnGOCoZjNcI1SPEoyOiUTHBYwflfAA5YgCA=', decoder=base64.urlsafe_b64decode)
public_key2 = private_key2.get_pubkey()

print(private_key1.to_bytes())

label = 'test-2'.encode('utf-8')

policy = api.create_policy(label, private_key1, public_key2, policy_expiration, m, n)

msg = 'Test message 1'.encode('utf-8')

data_source, message_kit, _signature = api.encrypt_for_policy(policy.public_key, msg)

data_source_public_key = UmbralPublicKey.from_bytes(bytes(data_source.stamp))

cleartext = api.decrypt_for_policy(label, message_kit, public_key1, private_key2, policy.public_key, data_source_public_key)

print(cleartext)
