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

def exists(params: [dict]) -> bool:
    client = CosmosClient.from_connection_string(os.environ["CosmosDBConnectionString"])
    container = client\
        .get_database_client("clover-db")\
        .get_container_client("user-wallets")
    
    q = "SELECT * FROM c WHERE c.google_nameidentifier = @param_google_nameidentifier"
    # logging.info("query", q)
    
    
    result_set = container.query_items(
        q,
        parameters=params,
        enable_cross_partition_query=True
        )
    
    return len(result_set) != 0 ### result_set is geen list type
    

def find_by_google_nameidentifier(client_principal) -> (bool, str):
    for claim in client_principal["claims"]:
        if "nameidentifier" in claim["typ"]:
            if exists(dict(name='@param_google_nameidentifier', value=claim["val"])): 
                raise exceptions.CosmosResourceExistsError("User already exists")

            return True, claim["val"]
    return False, None
