"""Validate Fig. 7 / Fig. 9 for an honest witness (m = 2). Scratch harness."""

import random

from radix_core.candidate_b.lattice import params, recursion as R, ring, subring

P_ = params.SMILE
Q = P_.modulus
L = P_.subring_dimension
K = P_.matrix_rows
ELL = P_.matrix_cols
KAPPA = P_.challenge_dim
LAMBDA = P_.masking_dim
M = 2
BLOCK = L
N = L**M
D = P_.ring_degree
H = D // L


def quartic(rng):
    return tuple(rng.randrange(Q) for _ in range(4))


def lift(vector):
    return subring.from_constants(tuple(v[0] for v in vector), P_)


def slots(poly):
    return subring.slots(poly, P_)


def add_all(polys):
    total = ring.zero(P_)
    for poly in polys:
        total = ring.add(total, poly, P_)
    return total


def e1_vector():
    return tuple((1, 0, 0, 0) if s == 0 else (0, 0, 0, 0) for s in range(BLOCK))


rng = random.Random(11)
A = tuple(tuple(ring.sample_uniform(rng) for _ in range(ELL)) for _ in range(K))
s_vec = ring.sample_vector(rng, ELL, small=True)
pk_iota = tuple(ring.dot(row, s_vec, P_) for row in A)
keys = [tuple(ring.sample_uniform(rng) for _ in range(K)) for _ in range(N)]
keys[0] = pk_iota
keys = tuple(keys)

c_prime = ring.sample_small(rng)
y_prime = ring.sample_vector(rng, ELL, small=True)
z_prime = tuple(ring.add(a, ring.mul(c_prime, b, P_), P_) for a, b in zip(y_prime, s_vec))
w_prime = tuple(ring.dot(row, y_prime, P_) for row in A)


def column(key):
    return tuple(
        element
        for poly in (ring.neg(ring.mul(c_prime, p, P_), P_) for p in key)
        for element in slots(poly)
    )


columns = [column(key) for key in keys]
P_matrix = tuple(tuple(columns[col][row] for col in range(N)) for row in range(K * BLOCK))

x1_polys = tuple(ring.sub(w_prime[i], ring.dot(A[i], z_prime, P_), P_) for i in range(K))
x1 = tuple(element for poly in x1_polys for element in slots(poly))

v_vectors = tuple(
    tuple((1 if s == i else 0, 0, 0, 0) for s in range(BLOCK)) for i in (0, 0)
)
v_polys = tuple(lift(vector) for vector in v_vectors)
tensor = R.tensor(v_vectors)
pu = tuple(
    tuple(sum(row[j][c] * tensor[j][0] for j in range(N)) % Q for c in range(4))
    for row in P_matrix
)
print("1. P.tensor == x1      :", pu == x1)

gamma1 = tuple(quartic(rng) for _ in range(K * BLOCK))
gamma1_polys = tuple(subring.glue(gamma1[i * BLOCK:(i + 1) * BLOCK], P_) for i in range(K))
P2 = R.reduce_matrix(gamma1, P_matrix, M)
x2_mq = R.matrix_vector(P2, v_vectors[1])
x2 = subring.glue(x2_mq, P_)
print("   (18) holds          :", R.pairing(pu, gamma1) == R.pairing(v_vectors[0], x2_mq))

y1 = ring.sub(
    ring.mul(v_polys[0], x2, P_),
    add_all(ring.mul(x1_polys[i], gamma1_polys[i], P_) for i in range(K)),
    P_,
)
print("2. g(y1) == 0          :", subring.g(y1) == (0, 0, 0, 0))

# ---- level m
gamma_m = tuple(quartic(rng) for _ in range((M + 1) * BLOCK))
g_m1 = subring.glue(gamma_m[:BLOCK], P_)
g_m2 = subring.glue(gamma_m[BLOCK:2 * BLOCK], P_)
g_m3 = subring.glue(gamma_m[2 * BLOCK:], P_)
ones_poly = lift(tuple((1, 0, 0, 0) for _ in range(BLOCK)))
tail = subring.glue(R.challenge_block(gamma_m[:BLOCK], P2), P_)
x3 = (
    ring.mul(g_m2, ones_poly, P_),
    ring.add(tail, ring.mul(g_m3, ones_poly, P_), P_),
)
y_m = ring.sub(
    ring.add(ring.mul(v_polys[0], x3[0], P_), ring.mul(v_polys[1], x3[1], P_), P_),
    ring.add(
        ring.mul(x2, g_m1, P_),
        ring.mul(lift(e1_vector()), ring.add(g_m2, g_m3, P_), P_),
        P_,
    ),
    P_,
)
print("3. g(y_m) == 0         :", subring.g(y_m) == (0, 0, 0, 0))

g_poly = ring.sample_small(rng)
g_poly = tuple(0 if i < H else g_poly[i] for i in range(D))
h = add_all((g_poly, y1, y_m))
print("4. h prefix zero       :", all(h[i] == 0 for i in range(H)))

# ---- commitments, line 04 adjustment, and equation 13
W = KAPPA + LAMBDA + K + 2 * M + 1
b_rows = [ring.sample_vector(rng, W, small=True) for _ in range(K + 2 * M + 1)]
mask = ring.sample_vector(rng, W, small=True)
rand = ring.sample_vector(rng, W, small=True)

values = {1: v_polys[0], 2: v_polys[1], 7: x2, 8: g_poly}
for i in range(K):
    values[3 + i] = w_prime[i]   # Fig. 7 commits w', then line 04 subtracts A z'
c = ring.sample_small(rng)
z = tuple(ring.add(a, ring.mul(c, b, P_), P_) for a, b in zip(mask, rand))
t = {i: ring.add(ring.dot(b_rows[i - 1], rand, P_), values[i], P_) for i in values}
for i in range(3, 3 + K):
    t[i] = ring.sub(t[i], ring.dot(A[i - 3], z_prime, P_), P_)   # Fig. 9 line 04
f = {i: ring.sub(ring.dot(b_rows[i - 1], z, P_), ring.mul(c, t[i], P_), P_) for i in values}
A_j = {i: ring.dot(b_rows[i - 1], mask, P_) for i in range(1, K + 2 * M + 2)}

F1 = ring.add(
    ring.mul(f[1], f[7], P_),
    ring.mul(c, add_all(ring.mul(gamma1_polys[i], f[3 + i], P_) for i in range(K)), P_),
    P_,
)
F2 = ring.sub(
    ring.mul(
        c,
        ring.sub(
            ring.mul(g_m1, f[7], P_),
            ring.add(ring.mul(x3[0], f[1], P_), ring.mul(x3[1], f[2], P_), P_),
            P_,
        ),
        P_,
    ),
    ring.mul(ring.mul(c, c, P_), ring.mul(lift(e1_vector()), ring.add(g_m2, g_m3, P_), P_), P_),
    P_,
)

psi1 = ring.sub(
    ring.sub(
        add_all(ring.mul(gamma1_polys[i], A_j[3 + i], P_) for i in range(K)),
        ring.mul(A_j[1], x2, P_),
        P_,
    ),
    ring.mul(A_j[7], v_polys[0], P_),
    P_,
)
psi_m = ring.sub(
    ring.mul(g_m1, A_j[7], P_),
    ring.add(ring.mul(x3[0], A_j[1], P_), ring.mul(x3[1], A_j[2], P_), P_),
    P_,
)
psi_sm = ring.sub(ring.add(psi1, psi_m, P_), A_j[8], P_)
omega_sm = ring.mul(A_j[1], A_j[7], P_)

alpha = [ring.sample_small(rng) for _ in range(M + 1)]
psi_bin = add_all(
    ring.mul(alpha[1 + i], ring.mul(A_j[1 + i], ring.sub(ring.constant(1), ring.scalar(2, v_polys[i], P_), P_), P_), P_)
    for i in range(M)
)
omega_bin = add_all(
    ring.mul(alpha[1 + i], ring.mul(A_j[1 + i], A_j[1 + i], P_), P_) for i in range(M)
)
psi = ring.add(ring.mul(alpha[0], psi_sm, P_), psi_bin, P_)
omega = ring.add(ring.add(ring.mul(alpha[0], omega_sm, P_), omega_bin, P_), A_j[K + 2 * M + 1], P_)

t_psi = ring.add(ring.dot(b_rows[K + 2 * M], rand, P_), psi, P_)
f_psi = ring.sub(ring.dot(b_rows[K + 2 * M], z, P_), ring.mul(c, t_psi, P_), P_)

lhs = ring.add(
    ring.add(
        ring.mul(
            alpha[0],
            ring.sub(ring.sub(ring.add(F1, F2, P_), ring.mul(c, f[8], P_), P_),
                     ring.mul(ring.mul(c, c, P_), h, P_), P_),
            P_,
        ),
        add_all(ring.mul(alpha[1 + i], ring.add(ring.mul(f[1 + i], f[1 + i], P_), ring.mul(c, f[1 + i], P_), P_), P_) for i in range(M)),
        P_,
    ),
    f_psi,
    P_,
)
print("5. line 13 holds       :", lhs == omega)

E0 = ring.sub(ring.add(ring.add(ring.mul(alpha[0], omega_sm, P_), omega_bin, P_), A_j[9], P_), omega, P_)
E1 = ring.sub(ring.add(ring.mul(alpha[0], psi_sm, P_), psi_bin, P_), psi, P_)
quad_bin = add_all(ring.mul(alpha[1 + i], ring.sub(ring.mul(v_polys[i], v_polys[i], P_), v_polys[i], P_), P_) for i in range(M))
E2 = ring.add(ring.mul(alpha[0], ring.sub(ring.add(ring.add(y1, y_m, P_), g_poly, P_), h, P_), P_), quad_bin, P_)
print("6. c^0 term           :", E0 == ring.zero(P_))
print("   c^1 term           :", E1 == ring.zero(P_))
print("   c^2 term           :", E2 == ring.zero(P_))
print("   F1 c2 vs y1        :", "checked via c^2 term")
print("   check E0+cE1+c2E2  :", ring.add(ring.add(E0, ring.mul(c, E1, P_), P_), ring.mul(ring.mul(c, c, P_), E2, P_), P_) == ring.sub(lhs, omega, P_))

closed = ring.add(
    ring.add(omega_sm, ring.mul(c, ring.add(psi1, psi_m, P_), P_), P_),
    ring.mul(ring.mul(c, c, P_), ring.add(y1, y_m, P_), P_),
    P_,
)
print("7. F1+F2 closed form  :", ring.add(F1, F2, P_) == closed)
if ring.add(F1, F2, P_) != closed:
    print("   F1 alone           :", F1 == ring.add(omega_sm, ring.mul(c, psi1, P_), P_))
    print("   F2 alone           :", F2 == ring.add(ring.mul(c, psi_m, P_), ring.mul(ring.mul(c, c, P_), y_m, P_), P_))

print("   f1 == A1 - c v1    :", f[1] == ring.sub(A_j[1], ring.mul(c, v_polys[0], P_), P_))
print("   f7 == A7 - c x2    :", f[7] == ring.sub(A_j[7], ring.mul(c, x2, P_), P_))
ok = [f[3 + i] == ring.sub(A_j[3 + i], ring.mul(c, x1_polys[i], P_), P_) for i in range(K)]
print("   f3..f6 adjusted    :", ok)
term = ring.mul(c, add_all(ring.mul(gamma1_polys[i], f[3 + i], P_) for i in range(K)), P_)
alt = ring.sub(
    ring.mul(c, add_all(ring.mul(gamma1_polys[i], A_j[3 + i], P_) for i in range(K)), P_),
    ring.mul(ring.mul(c, c, P_), add_all(ring.mul(gamma1_polys[i], x1_polys[i], P_) for i in range(K)), P_),
    P_,
)
print("   c*sum term         :", term == alt)

