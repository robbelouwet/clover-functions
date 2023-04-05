import rlp
from eth_utils import decode_hex


database = {
    "test_user": {
        "public_point": {
            "x": "0x548B896102A4A929B1FAA5C4F829613B9F565E126F65E9CFAFD3CC2AED960DC9",
            "y": "0x69C05126DBF83BA2E9419F45731FBCD12C31225F11189693A8D7F4B6C5A207A5"
        },
        'wallet': '0x3aDf15817991402Cf9f6829B3e9DED1a1E16c1f8',
        "server_x1": "0x85aa3a7a71ba6ec80474d5b206f4287c4526de0b2a8d2a250ff5c209dabaf8c3",
        "paillier": {
            "pk": "0x8ec318ec01cc7fd6db951c2e63f4ae0c665ca81fdc9d44940cd4871193aff295d7663e7277660a301a9a3760a277cfa81e580aa3fbebd4efce47dbe105f24bec443c55e224187c3f3f12a1fec93a781c787982ed2b1f2367b68e5ebbf386f8bed068ac6c90a723c53cf88d5dba13a361c84ad83e2e3b3eb5b690a8889ccf15aa10e00efe5be27726db10afd077933bd05968dd3b616f2ed4afc7fa3df8ba097a20beb788ff9cf18dcabd17ffbe083165a597646609833382b3e5428e4615943a6b85ef52e73a3ba6ed7a0dc361cb99efdeba5f7318d245d69cf3ff1cf2acdffbc31dff9ac76f1eb45a3f72b4077b4d7fabf77a34094271120367d2ee9d5375e7d795aec2e88c2fc5400fad3161a8c7c8b5a2cf9459a8b6bd710eb32014f0d2c1d6080a49d7c1362659b18c1f10a100589be65958ec44aec3ed4bfe98e8580f2a2900d710775dc2c3274e04171c7c3274a034acce621c5aeb50489bb7d12e86d231fbb4d8e7ab0e302509d28c15a40e95f920ace73cc8acd14a362798eadf6591",
            "sk": [
                "0x971e3172b00bbf3f117b25d687c5873bd18759b2d48f7f74d92418742c74afa5fea0ef50ea26f137189b1b842900e448c6e93a7a9370949cf27bb2c5190c076cc550787c3574c552056a7c0aa0eb9ed0a5f248d0503f799cd5750552e6176f2373eccb2cb888483a2ad99923ccf4af681bb40703310c017c89b7c8df98f027d3aee0b417a1faa757a6aa41f4aa36eb67d1f9a9a4b52f04a89463a67c7e8dd5ec854ac1b12dfe200f4e71f1810e3708191536aa9e182135849b00a955739a38df",
                "0xf1d848aacd8f5e721df49bf1ef8dcaa436bd828f2831620e28e9473e0938dac0322ec615bf53d4d9e869a6b4d7fad63416fbe29e4ff6c432d13ab21fb08a3be5e0b0759208aae7f7bebb74bfb6b56d54c1ef638cb29f5cf5b6348b9bf5b309c1f74a38072fab275bb6e66baaf7abcdb92497cd1db5f2bc3a084f6227387502d36d7a240f50d2f4314df7f590c981400aefb224e5162763ba8a4ec3cd9bb8e5d3f6916b664c2763210d276f4c94c559f3d7925426ba5a77b46c82b76de3dd7f8f"
            ]
        }
    }
}


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
