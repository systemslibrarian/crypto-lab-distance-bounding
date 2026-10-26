# Security policy and model

## Purpose

Distance Bounding is an educational, client-side protocol model. Do not use it to carry real anonymous messages, establish membership, protect identities, or operate a communications service.

## Modeled roles

- Five participants `A` through `E` occupy the declared key-sharing cycle `A-B-C-D-E-A`. Each endpoint knows the mask on its incident edge and each participant knows its own input.
- An outside observer knows the public graph and participant broadcasts but no edge mask or private input.
- A participant view adds that participant's input and incident masks.
- A coalition view pools its members' inputs and every mask incident to a coalition member.
- An omniscient simulator constructs fixtures and expected evidence. Its access to all secrets is not a capability of any learner-visible observer.

All roles execute in the same JavaScript realm. The view boundaries are data-model restrictions, not process, network, hardware, or trust isolation.

## Properties exercised

- Each honest participant XORs its equal-length input with every incident edge mask. Every complete honest round includes exactly one contribution per declared participant, so every edge mask appears twice and cancels.
- The aggregate is the bitwise XOR of participant inputs. It is not a sender count.
- For a declared observer, known-mask edges are removed and the remaining connected components define that observer's anonymity sets. The observer learns each component's input XOR and nothing stronger is claimed.
- Possible-sender filtering is performed only under an explicit exactly-one-sender hypothesis. Posterior weights retain and renormalize the declared priors rather than assuming a uniform sender distribution.
- A separate finite reference enumerates all mask assignments in small one-bit graphs and compares complete transcript distributions for compatible hypotheses.
- Validators refuse malformed membership, edges, lengths, contributions, and dropout rather than silently repairing them. The interactive honest path requests a new Web Crypto draw for every edge; its stateful guard separately rejects duplicate round identifiers and exact replay of a complete mask assignment, but byte-value comparison cannot prove that randomness was independently sampled.
- The attack path intentionally demonstrates that a correctly shaped arbitrary contribution can jam basic Distance Bounding without attribution.
- Reusing every mask incident to a participant exposes that participant's input XOR across the two transcripts. If one input is known to be empty, the other input is recovered directly.
- Later disclosure of incident masks can reduce a recorded round's anonymity and can reveal an individual past input once every incident mask is known.

## Randomness boundary

Chaum's unconditional claim assumes independent, uniformly distributed, secret, one-use key material. Interactive rounds use the browser's Web Crypto random generator as a concrete implementation. That API call is not a proof of uniformity, independence, physical entropy, secrecy, or erasure.

Deterministic test fixtures are injected explicitly. They are for reproducibility and independent checking, never represented as secure random generation.

JavaScript cannot guarantee that masks or nonces were erased from memory. The model does not claim forward secrecy for recorded broadcasts after key disclosure.

## Commitment adaptation

The optional commit/reveal exercise computes SHA-256 over a versioned, domain-separated, length-framed encoding that binds the participant label, membership, canonical key graph, session, round, contribution length, contribution, and a fresh 32-byte nonce. It is a bounded computational adaptation, not part of the information-theoretic masking argument.

Under the modeled ordering and the assumed collision and second-preimage resistance of SHA-256, a participant commits before seeing any reveal and cannot later open that digest to a different canonically encoded contribution or context. The fresh unpredictable 32-byte nonce raises the cost of enumerating the small contribution before reveal. This bounded construction has no formal hiding proof, and FIPS 180-4 specifies SHA-256 rather than proving this commitment construction secure.

The commitment does not establish who controls the participant label, prove that a contribution follows the Distance Bounding equation, prevent a party from committing to a jam, force a party to reveal, resolve a collision, or provide Dissent/Verdict-style blame or accountability.

## Deliberate nonclaims

The lab does not provide message confidentiality, receiver anonymity, source authentication, production identity or membership, Sybil resistance, transport privacy, availability, reliable collision detection, collision resolution, disruption accountability, durable erasure, persistent protocol state, traffic-analysis protection beyond the bounded transcript model, side-channel resistance, or compliance/FIPS validation.

The key-sharing graph is not the transport topology. The output and individual broadcasts are public in the model. A lone sender's message becomes the aggregate, and concurrent messages XOR; a collision can cancel, look corrupt, or accidentally look valid.

The finite enumerations and passing tests demonstrate the stated bounded implementation behavior. They do not prove computational hardness, browser entropy quality, or the complete asymptotic theorem.

## Dependency qualification

The deployed application has no runtime package dependency. It uses the browser's Web Crypto interface for random bytes and SHA-256. Development-only dependencies are locked in `package-lock.json`, audited in CI, and do not make the browser protocol production-ready.

## Reporting

Report a suspected vulnerability privately through the repository owner's established GitHub security contact. Do not include real user data, secrets, identity information, or credentials in an issue or demonstration.
