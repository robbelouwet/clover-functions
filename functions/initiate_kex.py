import os
import azure.functions as func
import logging
import json
from Crypto.Hash import keccak
from Crypto.Random import get_random_bytes
from ec_utils import secp256k1, to_secp256k1_point
from phe import EncryptedNumber, PaillierPublicKey, PaillierPrivateKey
from azure.cosmos import CosmosClient
from eth_utils import decode_hex
from functions.common import parse_principal_nameidentifier, find_by_google_nameidentifier, create_document
import base64


bp = func.Blueprint()


@bp.function_name(name="Initiate_KEX")
@bp.route(route="initiate-kex", methods=["PUT"])
def initiate_key_exchange(req: func.HttpRequest) -> func.HttpResponse:
    logging.info(f"x-ms-client-principal: {req.headers.get('x-ms-client-principal')}")

	# Parse client principal & google name
    client_principal = json.loads(base64.b64decode(req.headers.get('x-ms-client-principal')))
    success, id = parse_principal_nameidentifier(client_principal)
    if not success:
        return func.HttpResponse("Couldn't parse principal!", status_code=404)
    
	# user doc exists ?
    document = find_by_google_nameidentifier(id)
    if document is None:
           return func.HttpResponse("User not found!", status_code=404)
    logging.info(f"DOCUMENT: {document}")
    
	# Ephemeral key
    k1 = int.from_bytes(get_random_bytes(32), byteorder='big')
    R_server = k1 * secp256k1

    # Server's multiplicative share of secret key
    pk = PaillierPublicKey(int(document["paillier"]["pk"], 16))
    paillier_server_x = pk.encrypt(int(document['server_x'], 16))
    paillier_server_k = pk.encrypt(k1)

	# hmac to prevent malleability on server's ephemeral key
    paillier_server_k = hex(paillier_server_k._EncryptedNumber__ciphertext)
    hmac = keccak.new(digest_bits=256).update(bytearray.fromhex(hex(k1)[2:]))
    

    resp = {
        "paillier_server_x": hex(paillier_server_x._EncryptedNumber__ciphertext),
        "paillier_server_k": {
        	"value": paillier_server_k,
            "hmac": hmac.hexdigest()
		},
        "R_server": R_server.to_dict(),
        "paillier_pk": hex(pk.n),
    }

    create_document(document)

    # print(f"response:\n{json.dumps(resp, indent=4)}")

    return func.HttpResponse(json.dumps(resp), status_code=200)
