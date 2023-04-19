import os
import json
import uuid
import azure.functions as func
import logging
import json
from azure.cosmos import CosmosClient
from src.common import parse_principal_nameidentifier
from phe import paillier
import base64

bp = func.Blueprint()

#@login_required
@bp.function_name(name="Sign_Up")
@bp.route(route="sign-up", methods=["POST"])
def signup(req: func.HttpRequest) -> func.HttpResponse:

	client_principal = json.loads(base64.b64decode(req.headers.get('x-ms-client-principal')))
	logging.info(f"client principal:\n{client_principal}")
	success, id = parse_principal_nameidentifier(client_principal)

	if not success:
		return func.HttpResponse("", status_code=404)

	logging.info(client_principal)
	body = req.get_json()

	# Paillier key pair
	pk, sk = paillier.generate_paillier_keypair()
	

	client = CosmosClient.from_connection_string(os.environ["CosmosDBConnectionString"])
	container = client \
        .get_database_client("clover-db") \
        .get_container_client("user-wallets")
	
	doc = {
		"id": str(uuid.uuid4()),
		"google_nameidentifier": id,
		"wallet": body["wallet"],
		"server_x": body["server_x"],
		"paillier": {
			"pk": hex(pk.n),
			"sk": [
				hex(sk.p),
				hex(sk.q)
			]
		}
	}
		
	container.upsert_item(doc)

	return func.HttpResponse("", status_code=200)


