import azure.functions as func
import logging
from functions.initiate_kex import bp as bp1
from functions.push_signature import bp as bp2
from functions.signup import bp as bp3

app = func.FunctionApp()

app.register_functions(bp1)
app.register_functions(bp2)
app.register_functions(bp3)

@app.function_name(name="TestTrigger")
@app.route(route="test")
def main(req):
    return f'Hello, world!'
