# The estimator run

The outstanding item, and what actually blocks it.

**Summary: it is not blocked on cryptographers. It is blocked on SageMath, which does
not run natively on Windows.** Any Linux or macOS machine with Sage installed can do it
in about five minutes with the commands below.

---

## What was attempted, and what happened

Run on the Windows 11 machine, Python 3.14.3, empty WSL.

### `pip install lattice-estimator`

```
$ python -m pip install lattice-estimator
ERROR: Could not find a version that satisfies the requirement lattice-estimator
       (from versions: none)
ERROR: No matching distribution found for lattice-estimator
```

Not on PyPI. The project lives at `github.com/malb/lattice-estimator` and is installed
from source.

### `pip install git+https://github.com/malb/lattice-estimator.git`

Installs without error. Then:

```
$ python -c "import estimator"
ModuleNotFoundError: No module named 'sage'
```

The estimator is written against **SageMath**, not plain Python.

### `pip install fpylll`

```
error: failed-wheel-build-for-install
Failed to build installable wheels for some pyproject.toml based projects
       fpylll
```

`fpylll` needs a C++ toolchain (and `cysignals`); there is none on this machine, and
there are no wheels for Python 3.14.

### `wsl --status`

```
The Windows Subsystem for Linux is not installed.
```

So there is no Linux environment here to fall back on.

---

## What does work here

`experiments/estimate_sis.py` — the root-Hermite delta model, computed from the formulas
and **checked against the figures already published**, so nobody has to trust our
arithmetic:

```
$ python experiments/estimate_sis.py --check
relation                                   n  det^(1/n)      delta  block  classical   quantum
A (k=4, tagged width W=33)              1664     2^9.85   1.003218    541    2^158.0   2^143.3
B0 (W=33)                               4224     2^9.70   1.002992    598    2^174.7   2^158.5

check: both instances reproduce the published figures (2^158 and 2^175).
```

Writing it corrected two of my own errors, which is the argument for having it:

1. **Relation `A` uses `2*beta'`, not `2*beta`.** The extractor subtracts two responses
   from the *`z'`* mask over `MATRIX_COLS`, while `B_0` is bounded by `8*d*beta`. Mixing
   them gave `2^125.9` instead of `2^158` — a 32-bit error from one wrong variable.
2. **The published figures were truncated, not rounded.** `0.292 * 541 = 157.97`, and
   the first version of the document printed `2^157` because the formatting used `%d`.
   Both reviewers said `2^158`; they were right and the document was wrong.

**What the delta model is not:** a security proof, or a substitute for an estimator. It
assumes BKZ behaves as the geometric-series model says, ignores SVP-call costs, and
speaks to the *assumption*, not the scheme. `SECURITY-NOTES.md` says the same at length.

---

## What a working machine needs

Any of:

- **A Linux machine** (the spare Ubuntu laptop qualifies) with SageMath:
  `sudo apt-get install -y sagemath`
- **macOS** with Sage via Homebrew (`brew install sage`) or conda.
- **WSL2 on this machine**: `wsl --install -d Ubuntu`, then `apt-get install sagemath`.

Then:

```bash
git clone https://github.com/malb/lattice-estimator.git
cd lattice-estimator
sage -pip install -e .
sage -python -c "import estimator; print('ok')"
```

---

## The exact run

```python
from estimator import SIS, Q

q = 4294966337

# Relation A: k = 4 rows, ell = 13 columns over R_q, target 2*beta' = 193,024
SIS(d=4, n=13, q=q, m=4, length_bound=193024, norm=2)

# Relation B0: kappa = 10 rows, W = 33 columns, target 8*d*beta = 250,871,808
SIS(d=10, n=33, q=q, m=10, length_bound=250871808, norm=2)
```

Both are module-SIS over `R_q = Z_q[X]/(X^128+1)` with `d = 128`. The module
dimensions above are the unrolled dimensions divided by `d`; if the tool wants the
unrolled form, pass `n = 1664` and `n = 4224` with the same `length_bound`.

`python experiments/estimate_sis.py --homework` prints the current values from the code,
so this section cannot go stale after a parameter change.

---

## What to record

For each relation: the BKZ block size, the classical Core-SVP cost, the quantum
Core-SVP cost, and **which model** was used (Core-SVP, or a refined model with SVP call
costs). Then update:

- `SECURITY-NOTES.md` — replacing the delta-model paragraph with a measured one, and
  saying which model produced it.
- `STATUS.md` — the "no estimator run" row.
- `REVIEW-REQUEST.md` — the item that is currently open.

If the estimator disagrees with the delta model, **the estimator wins** and the
parameter conversation restarts. That is the point of running it.

---

## Related

- `experiments/estimate_sis.py` — the checked delta model and the estimator arguments
- [`SECURITY-NOTES.md`](../SECURITY-NOTES.md) — what the numbers mean and do not
- [`REVIEW-REQUEST.md`](../REVIEW-REQUEST.md) — where this was asked
