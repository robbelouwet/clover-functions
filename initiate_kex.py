import azure.functions as func
import logging
import json
from Crypto.Hash import keccak
from Crypto.Random import get_random_bytes
from ec_utils import secp256k1, to_secp256k1_point
from phe import EncryptedNumber, PaillierPublicKey, PaillierPrivateKey
from eth_utils import decode_hex
from azure.functions.authorization import login_required


bp = func.Blueprint()

# global_paillier_pk = PaillierPublicKey(
#     0x8ec318ec01cc7fd6db951c2e63f4ae0c665ca81fdc9d44940cd4871193aff295d7663e7277660a301a9a3760a277cfa81e580aa3fbebd4efce47dbe105f24bec443c55e224187c3f3f12a1fec93a781c787982ed2b1f2367b68e5ebbf386f8bed068ac6c90a723c53cf88d5dba13a361c84ad83e2e3b3eb5b690a8889ccf15aa10e00efe5be27726db10afd077933bd05968dd3b616f2ed4afc7fa3df8ba097a20beb788ff9cf18dcabd17ffbe083165a597646609833382b3e5428e4615943a6b85ef52e73a3ba6ed7a0dc361cb99efdeba5f7318d245d69cf3ff1cf2acdffbc31dff9ac76f1eb45a3f72b4077b4d7fabf77a34094271120367d2ee9d5375e7d795aec2e88c2fc5400fad3161a8c7c8b5a2cf9459a8b6bd710eb32014f0d2c1d6080a49d7c1362659b18c1f10a100589be65958ec44aec3ed4bfe98e8580f2a2900d710775dc2c3274e04171c7c3274a034acce621c5aeb50489bb7d12e86d231fbb4d8e7ab0e302509d28c15a40e95f920ace73cc8acd14a362798eadf6591)
# global_paillier_sk = PaillierPrivateKey(global_paillier_pk,
#                                         0x971e3172b00bbf3f117b25d687c5873bd18759b2d48f7f74d92418742c74afa5fea0ef50ea26f137189b1b842900e448c6e93a7a9370949cf27bb2c5190c076cc550787c3574c552056a7c0aa0eb9ed0a5f248d0503f799cd5750552e6176f2373eccb2cb888483a2ad99923ccf4af681bb40703310c017c89b7c8df98f027d3aee0b417a1faa757a6aa41f4aa36eb67d1f9a9a4b52f04a89463a67c7e8dd5ec854ac1b12dfe200f4e71f1810e3708191536aa9e182135849b00a955739a38df,
#                                         0xf1d848aacd8f5e721df49bf1ef8dcaa436bd828f2831620e28e9473e0938dac0322ec615bf53d4d9e869a6b4d7fad63416fbe29e4ff6c432d13ab21fb08a3be5e0b0759208aae7f7bebb74bfb6b56d54c1ef638cb29f5cf5b6348b9bf5b309c1f74a38072fab275bb6e66baaf7abcdb92497cd1db5f2bc3a084f6227387502d36d7a240f50d2f4314df7f590c981400aefb224e5162763ba8a4ec3cd9bb8e5d3f6916b664c2763210d276f4c94c559f3d7925426ba5a77b46c82b76de3dd7f8f)

#@login_required
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
    # Set the session key k
    # 39004532284663631990556472554068040036292738395773578375701065423956735386879

    logging.info(f"jwt: {req.headers.get('Authorization')}")

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

    # Paillier key pair
    # pk, sk = paillier.generate_paillier_keypair()
    # database["test_user"]["paillier"]["pk"] = pk
    # database["test_user"]["paillier"]["sk"] = sk

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

    # print(f"response:\n{json.dumps(resp, indent=4)}")

    return func.HttpResponse(json.dumps(resp), status_code=200)
