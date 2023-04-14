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


bp = func.Blueprint()


@bp.function_name(name="Initiate_KEX")
@bp.route(route="initiate-kex", methods=["PUT"])
def initiate_key_exchange(req: func.HttpRequest) -> func.HttpResponse:
    client = CosmosClient.from_connection_string(os.environ["CosmosDBConnectionString"])
    container = client\
        .get_database_client("clover-db")\
        .get_container_client("user-wallets")
    
    document = container.read_item("89dee130-6e2b-4066-8e66-7d2e132dc259", "89dee130-6e2b-4066-8e66-7d2e132dc259")

    logging.info(f"x-ms-client-principal: {req.headers.get('x-ms-client-principal')}")

    k1 = int.from_bytes(get_random_bytes(32), byteorder='big')

    # calculate R
    # x = int(req.params.get("x"), 16)
    # y = int(req.params.get("y"), 16)
    # document["wallet"] = req.params.get("wallet")
    R_server = k1 * secp256k1
    # print(f"R: {R}")
    # document['R'] = R.to_dict()

    # Paillier key pair
    # pk, sk = paillier.generate_paillier_keypair()
    # database["test_user"]["paillier"]["pk"] = pk
    # database["test_user"]["paillier"]["sk"] = sk

    # multiplicative share of server's x1 share
    pk = PaillierPublicKey(int(document["paillier"]["pk"], 16))
    paillier_server_x = pk.encrypt(int(document['server_x'], 16))
    paillier_server_k = pk.encrypt(k1)

    resp = {
        "paillier_server_x": hex(paillier_server_x._EncryptedNumber__ciphertext),
        "paillier_server_k": hex(paillier_server_k._EncryptedNumber__ciphertext),
        "R_server": R_server.to_dict(),
        "paillier_pk": hex(pk.n),
        
    }

    container.upsert_item(document)

    # print(f"response:\n{json.dumps(resp, indent=4)}")

    return func.HttpResponse(json.dumps(resp), status_code=200)
