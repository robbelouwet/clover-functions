import rlp
from eth_utils import decode_hex

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
