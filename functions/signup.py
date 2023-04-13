import os
import azure.functions as func
import logging
import json
from Crypto.Hash import keccak
from Crypto.Random import get_random_bytes
from ec_utils import secp256k1, to_secp256k1_point, verify_signature
from phe import EncryptedNumber, PaillierPublicKey, PaillierPrivateKey
from azure.cosmos import CosmosClient
from common import rlp_to_tx

bp = func.Blueprint()

#@login_required
@bp.function_name(name="Sign_Up")
@bp.route(route="sign-up", methods=["POST"])
def signup(req: func.HttpRequest) -> func.HttpResponse:
	logging.info(f"x-ms-client-principal: {req.headers.get('x-ms-client-principal')}")
	body = req.get_json()

	client = CosmosClient.from_connection_string(os.environ["CosmosDBConnectionString"])
	container = client \
        .get_database_client("clover-db") \
        .get_container_client("user-wallets")

	return func.HttpResponse({}, status_code=200)


