#! /usr/local/bin/python3
from schnorr_lib import *

# Notation of adaptor from:
# https://bitcoinops.org/en/topics/adaptor-signatures/

Adaptor = Tuple[int, Point, Point]

def point_equal(A: Optional[Point], B: Optional[Point]) -> bool:
    if x(A) == x(B):
        return True
    else:
        return False

def create_adaptor(msg: bytes, seckey: bytes, aux_rand: bytes, hidden: bytes) -> Optional[Adaptor]:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    if len(aux_rand) != 32:
        raise ValueError('aux_rand must be 32 bytes instead of %i.' % len(aux_rand))
    P = pubkey_gen(seckey)
    d = d0 if has_even_y(P) else n - d0
    P_point= lift_x(int_from_bytes(P))
    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", aux_rand))
    k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P_point) + msg)) % n
    R = point_mul(G, k0)
    assert R is not None
    k = k0
    # k = n - k0 if not has_even_y(R) else k0
    hidden_int = int_from_bytes(hidden) %n
    T = point_mul(G, hidden_int)
    # hidden_int = n - hidden_int0 if not has_even_y(T) else hidden_int0

    # R_plus_T = point_add(R,T)
    k_plus_t0 = (k+hidden_int) %n
    k_plus_t = k_plus_t0
    R_plus_T = point_mul(G,k_plus_t0)
    # k_plus_t = n - k_plus_t0 if not has_even_y(T) else k_plus_t0

    if not point_equal(R_plus_T, point_add(R,T)):
        print("WARNING: R_plus_T, point_add(R,T) are not equal!")
        print("R_plus_T",x(R_plus_T))
        print("point_add",x(point_add(R,T)))


    e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R_plus_T) + bytes_from_point(P) + msg)) % n
    ed = (e*d)%n
    eP = point_mul(G, ed)
    xeP = x(eP)
    s0 = ( k_plus_t + ed) % n # we don't compute it since not l
    S = point_mul(G,s0)
    s = s0
    # s = n - s0 if not has_even_y(R) else s0

    rhs=point_add(R_plus_T, eP)
    if point_equal(rhs,S):
        s_prime= (s - hidden_int) %n
        return (s_prime, R, T)
    else:
        print("rhs:", rhs,sep="\t")
        print("lhs:", S, sep="\t")
        raise ValueError("rhs and lhs are not equal")



def verify_adaptor(A: Optional[Adaptor], msg:bytes, pk:bytes,  hidden: bytes) -> bool:
    s_prime, R, T = A
    R_plus_T = point_add(R,T)

    P_point= lift_x(int_from_bytes(pk))
    hidden_int0 = int_from_bytes(hidden) %n
    T = point_mul(G, hidden_int0)
    hidden_int = hidden_int0
    s_plus_t = (s_prime + hidden_int) %n

    # (s + t) * G ?= R + T + H(R + T || P || m) * P
    e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R_plus_T) + bytes_from_point(pk) + msg)) % n
    eP = point_mul(P_point,e)
    eP_prime = point_mul(P_point,n-e)

    rhs = point_add(R_plus_T, eP)
    rhs_prime = point_add(R_plus_T, eP_prime)

    lhs = point_mul(G, s_plus_t)

    if point_equal(rhs,lhs) or point_equal(rhs_prime,lhs):
        return True
    else:
        print("rhs:", rhs,sep="\t")
        print("rhs_prime:", rhs_prime,sep="\t")
        print("lhs:", lhs_prime,sep="\t")
        return False


if __name__ == '__main__':

    # A = point_mul(G,2341321)
    # print("is A equal to A", point_equal(A,A))

    sk = os.urandom(32)
    pk = pubkey_gen(sk)
    aux = os.urandom(32)
    hidden = os.urandom(32)
    message = os.urandom(32)

    print("secret key is: ", sk.hex())
    print("public key is: ", pk.hex())
    print("aux is: ", aux.hex())
    print("hidden is: ", hidden.hex())
    print("message is: ", message.hex())
    print()

    print("Creating adaptor...")
    adaptor = create_adaptor(message, sk, aux, hidden)
    # print("adaptor message is", adaptor[0])
    # print("adaptor R is", adaptor[1])
    # print("adaptor T is", adaptor[2])

    print()
    print("Verifying adaptor...")
    flag = verify_adaptor(adaptor,message, pk, hidden)

    # shoud return true
    print("does the adaptor check out?", flag)

