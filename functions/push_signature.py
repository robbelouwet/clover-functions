import azure.functions as func
import logging
import json
from Crypto.Hash import keccak
from Crypto.Random import get_random_bytes
from ec_utils import secp256k1, to_secp256k1_point, verify_signature
from phe import EncryptedNumber, PaillierPublicKey, PaillierPrivateKey
from common import rlp_to_tx

bp = func.Blueprint()


#@login_required
@bp.function_name(name="Push_Sig")
@bp.route(route="push-sig", methods=["PUT"])
@bp.cosmos_db_input(
    arg_name="documents",
    database_name="clover-db",
    collection_name="user-wallets",
    connection_string_setting="CosmosDBConnectionString")
def push_partial_sig(req: func.HttpRequest, documents: func.DocumentList) -> func.HttpResponse:

    logging.info(f"x-ms-client-principal: {req.headers.get('x-ms-client-principal')}")

    # parse & save the transaction
    resp = req.get_json()
    tx_bytes = resp["tx"][2:]
    tx = rlp_to_tx(tx_bytes[2:])

    print("response:", json.dumps)

    # partial signature s'
    pk = PaillierPublicKey(int(documents[0]["paillier"]["pk"], 16))
    s_accent = EncryptedNumber(
        pk,
        int(resp["s_accent"], 16)
    )

    sk = PaillierPrivateKey(
        pk,
        int(documents[0]["paillier"]["sk"][0], 16),
        int(documents[0]["paillier"]["sk"][1], 16)
    )

    s_accent_decrypted = sk.decrypt(s_accent) % secp256k1.__n__

    k1 = sk.decrypt(EncryptedNumber(pk, int(resp["paillier_server_k"], 16)))
    R = documents[0]["R"]
    r = int(R["x"], 16)
    s = (pow(k1, -1, secp256k1.__n__) * s_accent_decrypted) % secp256k1.__n__
    yParity = int(R["y"], 16) % 2 == 0
    v = 28 - yParity  # 28 if even, 27 if uneven

    if s > secp256k1.__n__ / 2:  # ensure canonical s
        s = secp256k1.__n__ - s
        v = 55 - v  # 'flip' v if s is not canonical

    kec = keccak.new(digest_bits=256)
    kec.update(bytearray.fromhex(tx_bytes))
    h = kec.digest()

    # see if we have to flip v again if sig is invalid with this previous v
    if not verify_signature(documents[0]['wallet'], h, v, r, s):
        v = 55 - v  # 'flip' v

    return func.HttpResponse(
        json.dumps({'r': hex(r), 's': hex(s), 'v': hex(v)}),
        status_code=200
    )
