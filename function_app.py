import azure.functions as func
import logging
from initiate_kex import bp as bp1
from push_signature import bp as bp2

app = func.FunctionApp()

app.register_functions(bp1)
app.register_functions(bp2)


@app.function_name(name="HttpTrigger1")
@app.route(route="req")
def main(req):
    user = req.params.get('user')
    return f'Hello, {user}!'