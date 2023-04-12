import azure.functions as func
import logging
import json
from Crypto.Hash import keccak
from Crypto.Random import get_random_bytes
from ec_utils import secp256k1, to_secp256k1_point
from phe import EncryptedNumber, PaillierPublicKey, PaillierPrivateKey
from eth_utils import decode_hex


bp = func.Blueprint()

@bp.function_name(name="Initiate_KEX")
@bp.route(route="initiate-kex", methods=["PUT"])
@bp.cosmos_db_input(
    arg_name="documents",
    database_name="clover-db",
    collection_name="user-wallets",
    connection_string_setting="CosmosDBConnectionString")
@bp.cosmos_db_output(
    arg_name="outputDocument",
    database_name="clover-db",
    collection_name="user-wallets",
    create_if_not_exists=True,
    connection_string_setting="CosmosDBConnectionString")
def initiate_key_exchange(req: func.HttpRequest, documents: func.DocumentList, outputDocument: func.Out[func.Document]) -> func.HttpResponse:
    logging.info(f"x-ms-client-principal: {req.headers.get('x-ms-client-principal')}")

    document = documents[0]
    k1 = int.from_bytes(
        get_random_bytes(32), byteorder='big')

    # calculate R
    x = int(req.params.get("x"), 16)
    y = int(req.params.get("y"), 16)
    # document["wallet"] = req.params.get("wallet")
    R = k1 * to_secp256k1_point(x, y)
    # print(f"R: {R}")
    document['R'] = R.to_dict()

    # multiplicative share of server's x1 share
    pk = PaillierPublicKey(int(document["paillier"]["pk"], 16))
    paillier_x1 = pk.encrypt(int(document['server_x'], 16))
    k1_encrypted = pk.encrypt(k1)

    resp = {
        "paillier_server_x": hex(paillier_x1._EncryptedNumber__ciphertext),
        "paillier_server_k": hex(k1_encrypted._EncryptedNumber__ciphertext),
        "R": R.to_dict(),
        "paillier_pk": {
            "g": hex(pk.g),
            "max_int": hex(pk.max_int),
            "n": hex(pk.n),
            "nsquare": hex(pk.nsquare),
        }
    }

    outputDocument.set(document)
    
    return func.HttpResponse(json.dumps(resp), status_code=200)
