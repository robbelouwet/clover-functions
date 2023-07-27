import json
import azure.functions as func
import logging
import json
from src.common import parse_principal_nameidentifier, find_by_google_nameidentifier
import base64

bp = func.Blueprint()

#@login_required
@bp.function_name(name="Log_In")
@bp.route(route="log-in", methods=["GET"])
def signup(req: func.HttpRequest) -> func.HttpResponse:

	client_principal = json.loads(base64.b64decode(req.headers.get('x-ms-client-principal')))
	logging.info(f"client principal:\n{client_principal}")
	success, id = parse_principal_nameidentifier(client_principal)

	if not success:
		return func.HttpResponse("", status_code=404)
	
	usr = find_by_google_nameidentifier(id)

	return func.HttpResponse(usr["wallet"], status_code=200)


