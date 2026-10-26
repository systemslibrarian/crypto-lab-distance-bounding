# crypto-lab-distance-bounding

Executable distance-bounding and relay-attack teaching lab with deterministic timing models.

## What It Is

A browser-only lesson in the gap between **authentication** and **proximity**. A
verifier can confirm it is talking to the right key holder and still have no
idea where that key holder is. Hancke and Kuhn's 2005 protocol closes that gap
by timing a rapid single-bit exchange, so the round trip itself bounds the
distance.

The lab runs the original one-nonce, verifier-nonce protocol on **exact BigInt
rational arithmetic**, computes every attack probability as an exact fraction,
and drives six actor views: an honest prover, an ordinary HMAC-SHA-256
challenge-response that relays successfully, a Hancke-Kuhn online relay, mafia
fraud by pre-asking, distance fraud by a dishonest distant key holder, and an honest
prover on a noisy channel. Four broken controls are available as switches:
nonce reuse, predictable challenges, disabled timing, and an invalid
processing-delay lower bound.

## The protocol profile

Hancke and Kuhn 2005, §3.1, p. 69, with no variation:

```
V -> P : N_V                                     fresh, unpredictable, never reused
both   : R0 || R1 := h(K, N_V)                   two n-bit registers
for i = 1..n:
  V -> P : C_i in {0,1}                          unpredictable challenge bit
  P -> V : R_i^{C_i} in {0,1}                    immediate, from a 2-bit lookup
```

The paper's optional **prover-nonce** variant, where the registers come from
`h(K, N_V, N_P)` so neither nonce need be unpredictable, is **not implemented**.
It is named on the page, and the response-table grinding a prover-chosen nonce
would allow is listed among the limitations.

### The declared PRF instantiation

The paper does **not** mandate a primitive or a wire format. §3.2 says only that
`h` "may in a typical implementation be some form of secure (i.e. one-way and
collision-resistant) hash function", and that for larger `n` the registers may
come from "a secure pseudo random-bit generator seeded from the output of h".

This lab declares one instantiation and says so in the UI:

```
seed    = HMAC-SHA-256(K, DOMAIN || len(N_V) || N_V || len(n))
block_j = HMAC-SHA-256(seed, DOMAIN_EXPAND || be32(j))
R0 || R1 = first 2n bits of block_0 || block_1 || ...
```

Bits are taken most significant first within each byte; the first `n` are `R0`
and the next `n` are `R1`. SHA-256 and HMAC are hand-rolled so the model stays
synchronous and exactly replayable, and both are pinned against published
vectors: FIPS 180-4 Appendix B for SHA-256, RFC 4231 for HMAC, plus an
independent cross-check against Node's own implementation across every padding
boundary.

## Timing, in exact arithmetic

Grounded in Hancke and Kuhn §2, p. 68, equations (1) and (2), where `c` is the
propagation speed, `t_p` the one-way propagation time, `t_m` the measured round
trip and `t_d` the processing delay at the remote device:

```
(1)  d   = c (t_m - t_d) / 2
(2)  t_m = 2 t_p + t_d
```

Written here with `v` for the speed, `T` for the measured round trip and a
**trusted lower bound** `delta_lb` wherever the verifier must stand in for the
unknown `t_d`:

```
T_i   = tau_out + delta_P + tau_return
T_i   = 2D/v + delta_P                  symmetric direct path
Theta = 2R/v + delta_lb                 accept iff T_i <= Theta
D_hat = v (T_i - delta_lb) / 2          the displayed upper bound
```

**Units are abstract and declared by the scenario**: `v` is distance units per
time unit, `R` is distance units, every delay is time units. The default
profile uses `v = 1`, and the boundary is pinned by test: at `v = 1`, `R = 10`,
`delta_lb = 2` the threshold is exactly `22`, `T = 22` is accepted and `T = 23`
is rejected, with no rounding either side.

`D_hat` is a true upper bound **only while the prover cannot answer faster than
`delta_lb`**. If it can, the verifier subtracts delay that never happened and
the prover appears nearer than it is. That failure has its own executable
negative control, and the exact gain is `v (delta_lb - delta_actual) / 2`.

The distance-fraud actor commits to a response before it sees the challenge,
then begins the return transmission after challenge arrival. The model retains
both propagation legs and removes only the assumed processing delay. It does
not model a radio transmission scheduled before challenge arrival or the
physical synchronization needed for one.

**No browser or machine clock reaches a verdict.** `Date.now`,
`performance.now`, animation duration and real network latency are read nowhere
in the model; a unit test scans the model's own source to prove it, with a
positive control so the scan cannot pass by being broken, and a browser test
freezes and then skews both page clocks and requires the rendered transcript to
be byte-identical.

## Timing and content are checked separately

A late or missing answer is a **timing failure** and can never be absorbed by
the content-error allowance `x`. Any late round rejects the session even when
`x > 0`. Letting a late answer spend that allowance would turn a distance bound
back into an ordinary authentication exchange with extra steps, which is the
confusion the whole lab exists to undo.

## Exact probabilities

All computed as BigInt fractions; decimals appear beside them, never instead of
them. Hancke and Kuhn §3.4, p. 70 writes its two sums in terms of `k`, the
minimum number of correct responses; these are the same statements with
`x = n - k` tolerated errors.

| Quantity                       | Formula                                                      |
| ------------------------------ | ------------------------------------------------------------ |
| Mafia pre-ask                  | `4^-n * sum_{e=0..x} C(n,e) 3^(n-e)`                         |
| Blind responder                | `2^-n * sum_{e=0..x} C(n,e)`                                 |
| Partial pre-ask, `g` pre-asked | exact convolution over the two error counts                  |
| Distance fraud                 | `2^-h * sum_{e=0..min(x,h)} C(h,e)`, on the **realized** `h` |
| Honest false rejection         | `sum_{e=x+1..n} C(n,e) eps^e (1-eps)^(n-e)`                  |
| `q` fresh-nonce attempts       | `1 - (1-P)^q`                                                |

Pinned fixtures, each checked against exhaustive enumeration through `n = 8`:

| Case                                       | Exact value         |
| ------------------------------------------ | ------------------- |
| Mafia `n=8, x=0`                           | `6561/65536`        |
| Mafia `n=8, x=1`                           | `24057/65536`       |
| Blind `n=8, x=1`                           | `9/256`             |
| Partial pre-ask `n=8, g=4, x=0`            | `81/4096`           |
| Distance fraud `h=5, x=1`                  | `3/16`              |
| Honest `n=8, x=1, eps=1/8` acceptance      | `12353145/16777216` |
| Honest `n=8, x=1, eps=1/8` false rejection | `4424071/16777216`  |

Distance fraud is reported on the **realized** register distance
`h = HammingDistance(R0, R1)` for the session in front of you, with the ideal
ensemble average over `h ~ Binomial(n, 1/2)` shown beside it and never instead
of it. An average cannot tell a learner whether this session is the weak one.

`1 - (1-P)^q` is **refused** when the nonce is reused: the attempts are not
independent, and the function takes that independence as an explicit argument
rather than assuming it.

The independent-noise sampler realizes the displayed rational `eps` exactly:
it rejection-samples a uniform integer in `0..d-1` for reduced `eps = n/d` and
flips on exactly `n` outcomes. It does not silently replace `eps` by
`floor(eps * 2^k) / 2^k`. To keep an editable browser input bounded, `d` may be
at most `2^32`.

## The attacker knowledge boundary

The relay and mafia actors receive a `ProverOracle` — one function answering one
challenge in one round — and nothing else. They never receive the key, the
registers or the verifier's expected bits, there is no module-level state
holding any of those, and a unit test reads the attack module's own source to
confirm it imports no register derivation. A further test runs the complete
mafia attack against an oracle built from a key the attack code never sees.

The ordinary-authentication contrast separately computes
`HMAC-SHA-256(K, domain || challenge)`. Its relay receives only the challenge
oracle, returns the genuine tag, and has no key. A changed-tag negative control
fails authentication. This is a bounded comparison transcript, not a complete
deployed authentication protocol.

**Distance fraud is kept separate on purpose.** A distance-fraud actor _is_ the
legitimate key holder behaving dishonestly at a distance. It is not a relay,
there is no third party, and calling it mafia fraud — which several informal
accounts do — misdescribes both the attacker and the defence.

## What this lab does not do

- It is an **arithmetic and event simulator**, not ranging hardware, and it
  contains no radio.
- It **does not establish physical location** and **does not measure nanosecond
  radio propagation**.
- The exact probabilities assume ideal independent PRF output bits, a fresh
  unpredictable verifier nonce, and unpredictable challenges. Where an
  experiment breaks one of those, the page retires the inapplicable formula and
  prints only a newly justified exact case, if one exists.
- A **prover-chosen nonce** may allow response-table grinding. Named, not
  modelled.
- Real jitter, multipath, non-line-of-sight propagation, interference,
  correlated or bursty errors and radio capture effects are **not modelled**.
  The noise model flips each response bit independently, which real channels do
  not.
- The distance-fraud timing model keeps both propagation legs, begins the return
  trip after challenge arrival, and omits only processing delay. Scheduled
  pre-transmission and physical synchronization attacks are outside it.
- **Early-detect and late-commit** behaviour depends on physical-layer symbol
  timing and sits outside the executable core (Clulow et al. 2006).
- **Terrorist fraud**, collusion, localisation and production parameter
  selection are out of scope.
- **Brands-Chaum is referenced for comparison only** and is not implemented.
- Looking random is not evidence of pseudorandomness. The lab runs no
  statistical test that could be mistaken for a proof.

## Primary sources

Read rather than summarised; the sections used are listed on the page itself.

- **G. P. Hancke and M. G. Kuhn, "An RFID Distance Bounding Protocol",
  SecureComm 2005, Athens, 5-9 September 2005, pp. 67-73, IEEE Computer Society
  Press, ISBN 0-7695-2369-2.**
  [PDF](https://www.cl.cam.ac.uk/~mgk25/sc2005-distance.pdf). §2 p. 68
  equations (1) and (2); §3.1 p. 69 the protocol, the 3/4 per-round bound and
  the prover-nonce variant; §3.2 p. 70 the function `h` and its parameters;
  §3.4 p. 70 the false-accept and false-reject sums.
- **S. Brands and D. Chaum, "Distance-Bounding Protocols", EUROCRYPT '93, LNCS
  765, pp. 344-359.**
  [PDF](https://link.springer.com/content/pdf/10.1007/3-540-48285-7_30.pdf).
  Comparison only.
- **J. Clulow, G. P. Hancke, M. G. Kuhn and T. Moore, "So Near and Yet So Far:
  Distance-Bounding Attacks in Wireless Networks", ESAS 2006.**
  [PDF](https://www.cl.cam.ac.uk/~mgk25/esas2006-distance.pdf). Early-detect
  and late-commit, named and left outside the executable core.
- **G. Avoine, M. A. Bingöl, S. Kardaş, C. Lauradoux and B. Martin, "A Framework
  for Analyzing RFID Distance Bounding Protocols", Journal of Computer
  Security, 2010.**
  [PDF](https://sites.uclouvain.be/security/download/papers/AvoineBKLM-2010-jcs.pdf).
  The adversary vocabulary, including the separation of mafia fraud from
  distance fraud.
- **O. Kara, S. Kardaş, M. A. Bingöl and G. Avoine, "Optimal Security Limits of
  RFID Distance Bounding Protocols".**
  [PDF](https://research.sabanciuniv.edu/id/eprint/15328/1/optimal.pdf).
  Security limits for bitwise fast-phase protocols with no final signature,
  the class this protocol belongs to.
- **D. Singelée and B. Preneel, "Distance Bounding in Noisy Environments".**
  [PDF](https://cosicdatabase.esat.kuleuven.be/backend/publications/files/conferencepaper/919).
  Tolerating channel errors without handing the attacker the allowance.

## Build and verify

Node 22, 24 or 26 and newer:

```sh
npm ci
npm run ci              # format, typecheck, lint, coverage, build
npx playwright install chromium
npm run test:claims     # browser claims, recomputed independently
npm run test:a11y       # axe, contrast and reflow, pinned dark palette
npm run test:mutations  # clean-baseline source mutations
```

Coverage thresholds for `src/db/**` are statements 95, branches 90, functions
95 and lines 95; the suite runs above all four. The browser claim tests
recompute the threshold, the round trips, the register distance and every
displayed probability with arithmetic written inside the test file, so a figure
is checked against an independent computation rather than against the code that
produced it. Eleven source mutations must each build, move the bundle bytes,
fail one **named** owning assertion as an ordinary test failure, restore byte
for byte, rebuild to the baseline digest and pass again.

### Theming

The lab follows the fleet contract: one dark theme is pinned in the root HTML,
with no toggle and no stored or operating-system preference that can change it.
The accessibility gate scans that same pinned palette under both dark and light
OS preferences so a stray media-query branch cannot escape.

---

_One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite._

_"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31_
