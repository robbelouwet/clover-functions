import azure.functions as func
from azure.core import exceptions
import logging
import json
from Crypto.Hash import keccak
from Crypto.Random import get_random_bytes
from src.ec_utils import secp256k1, to_secp256k1_point, verify_signature
from phe import EncryptedNumber, PaillierPublicKey, PaillierPrivateKey
from azure.cosmos import CosmosClient
from src.common import rlp_to_tx, find_by_google_nameidentifier, parse_principal_nameidentifier
import base64

bp = func.Blueprint()


#@login_required
@bp.function_name(name="Push_Sig")
@bp.route(route="push-sig", methods=["PUT"])
def push_partial_sig(req: func.HttpRequest) -> func.HttpResponse:
    logging.info(f"x-ms-client-principal: {req.headers.get('x-ms-client-principal')}")    

    client_principal = json.loads(base64.b64decode(req.headers.get('x-ms-client-principal')))
    logging.info(f"client principal:\n{client_principal}")
    success, id = parse_principal_nameidentifier(client_principal)
    
    if not success:
        return func.HttpResponse("Couldn't parse user principal!", status_code=404)
    
    document = find_by_google_nameidentifier(id)
    if document is None:
        return func.HttpResponse("User not found!", status_code=404)
    
    # parse the transaction
    resp = req.get_json()
    tx_bytes = resp["tx"][2:]
    tx = rlp_to_tx(tx_bytes[2:])

    # partial signature s'
    pk = PaillierPublicKey(int(document["paillier"]["pk"], 16))
    s_accent = EncryptedNumber(
        pk,
        int(resp["s_accent"], 16)
    )

    sk = PaillierPrivateKey(
        pk,
        int(document["paillier"]["sk"][0], 16),
        int(document["paillier"]["sk"][1], 16)
    )
    
	# verify data origin authentication of server's ephemeral key
    retrieved_hash = resp["paillier_server_k"]["hmac"]
    k1 = sk.decrypt(EncryptedNumber(pk, int(resp["paillier_server_k"]["value"], 16)))
    hash_input = f"{hex(k1)[2:]}{document['server_x'][2:]}"  # append ephemeral key with server's share without preceding '0x' as hash pre-image
    reconstructed_hmac = keccak\
        .new(digest_bits=256)\
        .update(bytearray.fromhex(hash_input))\
        .hexdigest()
    if not retrieved_hash == reconstructed_hmac:
        return func.HttpResponse("", status_code=401)
    

    s_accent_decrypted = sk.decrypt(s_accent) % secp256k1.__n__
    
    R = k1 * to_secp256k1_point(int(resp["R_client"]["x"], 16), int(resp["R_client"]["y"], 16))
    r = R.__x__
    s = (pow(k1, -1, secp256k1.__n__) * s_accent_decrypted) % secp256k1.__n__
    yParity = R.__y__ % 2 == 0
    v = 28 - yParity  # 28 if even, 27 if uneven

    if s > secp256k1.__n__ / 2:  # ensure canonical s
        s = secp256k1.__n__ - s
        v = 55 - v  # 'flip' v if s is not canonical

    kec = keccak.new(digest_bits=256)
    kec.update(bytearray.fromhex(tx_bytes))

    logging.info(f"signing 0x{kec.hexdigest()}")

    # see if we have to flip v again if sig is invalid with this previous v
    if not verify_signature(document['wallet'], kec.digest(), v, r, s):
        v = 55 - v  # 'flip' v

    if not verify_signature(document['wallet'], kec.digest(), v, r, s):
        return func.HttpResponse("Invalid signature", status_code=400)

    return func.HttpResponse(
        json.dumps({'r': hex(r), 's': hex(s), 'v': hex(v)}),
        status_code=200
    )
