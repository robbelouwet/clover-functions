import azure.functions as func
import logging
import json
from Crypto.Random import get_random_bytes
from src.ec_utils import secp256k1
from phe import PaillierPublicKey
from src.common import parse_principal_nameidentifier, find_by_google_nameidentifier, create_document
import base64


bp = func.Blueprint()


@bp.function_name(name="Initiate_KEX")
@bp.route(route="initiate-kex", methods=["PUT"])
def initiate_key_exchange(req: func.HttpRequest) -> func.HttpResponse:    
    client_principal = json.loads(base64.b64decode(req.headers.get('x-ms-client-principal')))
    success, id = parse_principal_nameidentifier(client_principal)

    if not success:
        return func.HttpResponse("", status_code=404)
    
    document = find_by_google_nameidentifier(id)
    logging.info(f"DOCUMENT: {document}")

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

    create_document(document)

    # print(f"response:\n{json.dumps(resp, indent=4)}")

    return func.HttpResponse(json.dumps(resp), status_code=200)
