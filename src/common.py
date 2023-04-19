import os
import rlp
import logging
from eth_utils import decode_hex
from azure.cosmos import CosmosClient, exceptions

def rlp_to_tx(b: str):
    tx = rlp.decode(decode_hex(b))
    t = dict(
        chainId=int.from_bytes(tx[0], "big"),
        nonce=int.from_bytes(tx[1], "big"),
        maxpriorityFeePerGas=int.from_bytes(tx[2], "big"),
        maxFeePerGas=None if tx[3] == b'' else int.from_bytes(tx[3], "big"),
        gasLimit=int.from_bytes(tx[4], "big"),
        to="0x" + tx[5].hex(),
        value=int.from_bytes(tx[6], "big"),
        data=tx[7],
        type=2
    )
    return t


def find_by_google_nameidentifier(id: str) -> dict:
    client = CosmosClient.from_connection_string(os.environ["CosmosDBConnectionString"])
    container = client\
        .get_database_client("clover-db")\
        .get_container_client("user-wallets")
    
    q = f'SELECT * FROM c WHERE c.google_nameidentifier = @param_google_nameidentifier'
    # logging.info("query", q)
    
    
    result_set = container.query_items(
        q,
        parameters=[dict(name='@param_google_nameidentifier', value=id)],
        enable_cross_partition_query=True
        )
    
    results = [doc for doc in result_set]
    if len(results) == 0: raise exceptions.CosmosResourceNotFoundError()
    elif len(results) > 1: raise exceptions.CosmosAccessConditionFailedError(message="Multiple hits found!")

    return results[0]

def create_document(v: dict):
    client = CosmosClient.from_connection_string(os.environ["CosmosDBConnectionString"])
    container = client\
        .get_database_client("clover-db")\
        .get_container_client("user-wallets")
    
    container.upsert_item(v)
    

def parse_principal_nameidentifier(client_principal) -> str:
    for claim in client_principal["claims"]:
        if "nameidentifier" in claim["typ"]:
            return True, claim["val"]
    return False, None
