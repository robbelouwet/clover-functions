import logging
from Crypto.Hash import keccak
from ethereum.utils import ecrecover_to_pub
from web3 import Web3


class Point(object):
    def __init__(self, curve, G: (int, int), q, n):
        self.__curve__ = curve
        self.__n__ = n
        self.__q__ = q
        self.__x__ = G[0]
        self.__y__ = G[1]

    def __add__(self, other):
        # P (+) Inf
        if isinstance(other, Infinity):
            return self

        # P (+) P
        if other.__x__ == self.__x__ and other.__y__ == self.__y__:
            return self.__add_identity__(other)

        # P (+) -P
        if other.__x__ == self.__x__ and not other.__y__ == self.__y__:
            return Infinity(self.__curve__, self.__q__, self.__n__)

        # P (+) Q
        else:
            return self.__add_diff__(other)

    def __mul__(self, n):
        if not isinstance(n, int):
            raise RuntimeError("Multiplying 2 points...")

        r = Infinity(self.__curve__, self.__q__, self.__n__)
        q = self

        while n > 0:
            if n & 1:
                r += q
            q += q
            n >>= 1

        return r

    def __rmul__(self, other):
        return self.__mul__(other)

    def __verify__(self):
        return (self.__y__ ** 2) % self.__q__ \
               == \
               (self.__x__ ** 3 + self.__curve__[0] * self.__x__ + self.__curve__[1]) % self.__q__

    def __add_diff__(self, other):
        # print("Adding 2 different points")
        x2 = other.__x__
        y2 = other.__y__
        assert self.__n__ == other.__n__

        x1 = self.__x__
        y1 = self.__y__

        delta_teller = y2 - y1
        delta_noemer = x2 - x1

        delta = (delta_teller * pow(delta_noemer, -1, self.__q__)) % self.__q__

        x3 = ((delta ** 2) - x1 - x2) % self.__q__
        y3 = (delta * (x1 - x3) - y1) % self.__q__

        return Point(self.__curve__, (x3, y3), self.__q__, self.__n__)

    def __add_identity__(self, p: (int, int)) -> (int, int):
        # print("Adding to itself...")
        x1 = x2 = p.__x__
        y1 = p.__y__

        delta_teller = 3 * (x1 ** 2) + self.__curve__[0]
        delta_noemer = 2 * y1

        delta = (delta_teller * pow(delta_noemer, -1, self.__q__)) % self.__q__

        x3 = (delta ** 2 - x1 - x2) % self.__q__
        y3 = (delta * (x1 - x3) - y1) % self.__q__

        return Point(self.__curve__, (x3, y3), self.__q__, self.__n__)

    def __radd__(self, other):
        return self.__add__(other)

    def __str__(self):
        return f"({hex(self.__x__)}, {hex(self.__y__)})"

    def to_dict(self):
        return {
            "x": hex(self.__x__),
            "y": hex(self.__y__)
        }

    def extract_wallet(self):
        public_point_bytes = bytearray.fromhex(f"{self.__x__:064x}{self.__y__:064x}")
        wallet_hash = keccak.new(digest_bits=256)
        wallet_hash.update(public_point_bytes)
        full_wallet = wallet_hash.hexdigest()

        # take the first 40 bits
        return Web3.to_checksum_address(full_wallet[-40:])


class Infinity(Point):

    def __init__(self, curve: (int, int), n: int, order: int):
        super().__init__(curve, (None, None), n, order)

        self.__curve__ = curve
        self.__n__ = n

    def __add__(self, other):
        return other

    def __radd__(self, other):
        return self.__add__(other)

    def __str__(self):
        return "Inf"


secp256k1 = Point((0, 7),
                  (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                   0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
                  2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1,
                  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)


def verify_signature(wallet: str, h: bytes, v: int, r: int, s: int) -> bool:
    wallet_hash = keccak.new(digest_bits=256)
    wallet_hash.update(ecrecover_to_pub(h, v, r, s))
    recovered_wallet = "0x" + wallet_hash.hexdigest()[-40:]
    logging.info(f"ec_utils:verify_signature, recovered wallet: {recovered_wallet}")
    return recovered_wallet == wallet.lower()


def to_secp256k1_point(x: int, y: int) -> Point:
    return Point(
        secp256k1.__curve__,
        (x, y),
        secp256k1.__q__,
        secp256k1.__n__
    )
