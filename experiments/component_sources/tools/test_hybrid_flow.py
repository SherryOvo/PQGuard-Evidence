"""Regression test for hybrid_kem_benchmark using a role-correct fake KEM.

The fake KEM only returns the correct shared secret when the decapsulating
object holds the secret key matching the public key the ciphertext was
encapsulated to. That models the real KEM contract and lets us check, without
liboqs installed, that

  * the corrected benchmark performs valid exchanges, and
  * the old prototype's defect (decapsulating with a freshly generated key pair)
    is caught by the agreement gate rather than silently producing numbers.
"""
import sys, types, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hybrid_kem_benchmark as H

class FakeKEM:
    """Toy KEM: a ciphertext decapsulates correctly only with its own secret key."""
    _counter = 0
    def __init__(self, mech):
        self.mech = mech
        self._sk = None
    def generate_keypair(self):
        FakeKEM._counter += 1
        n = FakeKEM._counter
        self._sk = n
        return f"pk{n}".encode()
    def encap_secret(self, pk):
        m = int(pk[2:])
        return f"ct{m}".encode(), b"ss%d" % m           # secret binds to the pk
    def decap_secret(self, ct):
        m = int(ct[2:])
        if self._sk != m:                               # wrong secret -> wrong secret
            return b"WRONG"
        return b"ss%d" % m

class FakeOQS:
    KeyEncapsulation = FakeKEM
    @staticmethod
    def get_enabled_kem_mechanisms(): return ["ML-KEM-768"]

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

backend = {"oqs": FakeOQS, "X25519PrivateKey": X25519PrivateKey,
           "X25519PublicKey": X25519PublicKey, "HKDF": HKDF, "hashes": hashes,
           "Encoding": Encoding, "PublicFormat": PublicFormat}

ok = 0; fail = 0
def chk(name, cond):
    global ok, fail
    print(("  [OK]   " if cond else "  [FAIL] ") + name)
    ok += cond; fail += (not cond)

print("A. pure_mlkem 控制流（每次 decap 都用配套密钥）")
r = H.pure_mlkem(backend, repeats=5)
chk("pure 路径通过共享密钥一致性闸门", r["shared_secret_agreement"] is True)
chk("encapsulate 有 5 个样本", r["encapsulate"]["n"] == 5)
chk("decapsulate 有 5 个样本", r["decapsulate"]["n"] == 5)

print("\nB. hybrid 控制流（两端共享密钥一致）")
h = H.hybrid_x25519_mlkem(backend, repeats=5)
chk("X25519 一致", h["x25519_shared_secret_agreement"] is True)
chk("ML-KEM 一致", h["mlkem_shared_secret_agreement"] is True)
chk("组合器一致", h["combiner_agreement"] is True)
chk("responder 5 样本", h["responder_side"]["n"] == 5)
chk("initiator 5 样本", h["initiator_side"]["n"] == 5)

print("\nC. 反向验证：旧代码那种「用不匹配密钥解封装」必须被闸门拦住")
class MismatchKEM(FakeKEM):
    def decap_secret(self, ct):
        # 模拟旧代码：无论 ct 是什么，都用另一把新生成的密钥
        return b"WRONG"
backend_bad = dict(backend); 
class BadOQS(FakeOQS):
    KeyEncapsulation = MismatchKEM
backend_bad["oqs"] = BadOQS
try:
    H.pure_mlkem(backend_bad, repeats=2)
    chk("不匹配密钥被拒绝", False)
except RuntimeError as e:
    chk(f"不匹配密钥被拒绝（{str(e)[:40]}…）", True)

print(f"\n=== {ok} passed, {fail} failed ===")
sys.exit(1 if fail else 0)
