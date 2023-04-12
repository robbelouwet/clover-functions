import azure.functions as func
import logging

bp = func.Blueprint()

#@login_required
@bp.function_name(name="Sign_Up")
@bp.route(route="sign-up", methods=["POST"])
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
def signup(req: func.HttpRequest, documents: func.DocumentList, outputDocument: func.Out[func.Document]) -> func.HttpResponse:
	logging.info(f"x-ms-client-principal: {req.headers.get('x-ms-client-principal')}")

	return func.HttpResponse({}, status_code=200)


