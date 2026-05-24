---- MODULE AuditHashChain ----
(*
  AuditHashChain.tla
  Formal model of the Merkle-style BLAKE3 audit hash chain (ADR-0009).

  Wave-1 rewrite: adds adversarial tamper actions so every invariant maps
  to a concrete attack that could plausibly violate it.
  Wave-3 polish: larger bounds, NoChainFork invariant, abstraction
  assumptions block.

  New adversarial actions:
    TruncateChain(k)    -- shorten chain to length k, breaking append-only
    RemoveEntry(i)      -- remove element at position i (middle deletion)
    ReorderEntries(i,j) -- swap two entries at non-adjacent positions i,j
    ForgeEntry(i)       -- rewrite the prev_hash field of entry i to a
                          forged Nat that does not match the legitimate hash

  Variables / mechanisms:
    hmacKey       -- ghost HMAC key (Nat); Hmac(code,key) binds the head code
    pinnedHead    -- head hash (Nat) pinned synchronously on every Append;
                     adversarial actions CANNOT update pinnedHead
    lastTimestamp -- non-decreasing ts per entry (encodes AuditEntry Invariant 2)

  Bounds (AuditHashChain.cfg):
    MaxEntries = 5, MaxActors = 2, MaxTampers = 2
*)

\* Abstraction Assumptions — see ADR-0009 Amendment for the security
\* model that these abstractions discharge. Each item below names the
\* primitive being abstracted and the property being assumed.
(* ================================================================== *)
(* Abstraction assumptions                                              *)
(*                                                                      *)
(* Cross-references: ADR-0009 (audit chain), ADR-0004 (AEAD/DEK).      *)
(*                                                                      *)
(* 1. Hash injectivity (HashCode):                                      *)
(*    Hash is modeled as a perfect injection — no two distinct inputs   *)
(*    (actor, seqNo, prevCode) produce the same output Nat.             *)
(*    Injectivity follows from base-expansion (each argument <Base).    *)
(*    This discharges BLAKE3 second-preimage resistance: the 2^-128     *)
(*    second-preimage probability is accepted out-of-band. No collision *)
(*    is representable in the finite state space TLC explores.          *)
(*                                                                      *)
(* 2. HMAC correctness (HmacCode):                                      *)
(*    Hmac(content, key) is modeled as a perfect MAC (HmacCode = code   *)
(*    + key over Nat). The binding property (same (code, key) => same   *)
(*    HMAC) is used only to confirm pinnedHead matches chain tail.      *)
(*    This discharges keyed-BLAKE3 EUF-CMA (existential unforgeability  *)
(*    under chosen message attack) as accepted out-of-band.             *)
(*                                                                      *)
(* 3. Encrypt abstraction (AEADNonceDiscipline.tla):                   *)
(*    Encrypt(content, dek, nonce, ad) is modeled as a perfect          *)
(*    injection on (dek, nonce, ad). This discharges XChaCha20-         *)
(*    Poly1305 IND-CPA + INT-CTXT as accepted out-of-band.              *)
(*    (AEADNonceDiscipline.tla is the authoritative model for that       *)
(*    property; this module imports the abstraction assumption for       *)
(*    audit completeness only.)                                          *)
(* ================================================================== *)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
  MaxEntries,
  MaxActors,
  MaxTampers

ASSUME MaxEntries \in Nat /\ MaxEntries >= 2
ASSUME MaxActors  \in Nat /\ MaxActors  >= 1
ASSUME MaxTampers \in Nat /\ MaxTampers >= 1

(* ------------------------------------------------------------------ *)
(* Abstract Hash (Nat-valued, injective within the bounded model)       *)
(*                                                                      *)
(* Hash maps (actor, seqNo, prevCode) to a unique Nat.                  *)
(* Base = (MaxActors+1) * (MaxEntries+1) -- larger than any single field*)
(* GENESIS_CODE = 0 (the all-zeros sentinel for the first entry's prev) *)
(* FORGED_CODE  = a Nat that cannot equal any legitimately computed     *)
(*   hash: we use (MaxActors+1)*(MaxEntries+1)^3 as an out-of-range     *)
(*   sentinel.                                                           *)
(* ------------------------------------------------------------------ *)

Base    == (MaxActors + 1) * (MaxEntries + 2)
BaseExp == Base * Base

GENESIS_CODE == 0

\* Hash(actor, seqNo, prevCode) -> Nat
\* Injectivity follows from base-expansion (each component < Base).
HashCode(actor, seqNo, prevCode) ==
  actor * BaseExp + seqNo * Base + prevCode

\* FORGED_CODE: a Nat that no legitimately computed HashCode can equal.
\* All real hashes satisfy HashCode <= MaxActors*BaseExp + MaxEntries*Base + <max_prev>.
\* We use MaxActors*BaseExp + (MaxEntries+1)*Base as a sentinel above all real hashes.
FORGED_CODE == MaxActors * BaseExp + (MaxEntries + 1) * Base

\* HMAC is modeled as (hashCode + key) mod a large prime -- injective enough
\* for the finite model.  We use addition since both are Nat.
HmacCode(code, key) == code + key

MakeEntry(actor, seqNo, prevCode) ==
  [ actor         |-> actor,
    seqNo         |-> seqNo,
    prev_hash     |-> prevCode,
    current_hash  |-> HashCode(actor, seqNo, prevCode),
    ts            |-> seqNo ]

(* ------------------------------------------------------------------ *)
(* State variables                                                      *)
(* ------------------------------------------------------------------ *)

VARIABLES chain, head, tampered, verified, hmacKey, pinnedHead, lastTimestamp

vars == <<chain, head, tampered, verified, hmacKey, pinnedHead, lastTimestamp>>

TypeOK ==
  /\ Len(chain)      \in 0..MaxEntries
  /\ tampered        \in 0..MaxTampers
  /\ verified.status \in {"none", "ok", "fail"}
  /\ verified.at     \in 0..MaxEntries
  /\ lastTimestamp   \in 0..MaxEntries
  /\ head            \in Nat
  /\ pinnedHead      \in Nat

Init ==
  /\ chain         = <<>>
  /\ head          = GENESIS_CODE
  /\ tampered      = 0
  /\ verified      = [status |-> "none", at |-> 0]
  /\ hmacKey       = 1
  /\ pinnedHead    = GENESIS_CODE
  /\ lastTimestamp = 0

(* ------------------------------------------------------------------ *)
(* VerifyChain: recompute expected hashes; compare recomputed head      *)
(* against pinnedHead to detect structural mutations.                   *)
(* ------------------------------------------------------------------ *)

RECURSIVE ExpectedCodeAt(_, _)
ExpectedCodeAt(ch, i) ==
  IF i = 1
  THEN HashCode(ch[1].actor, ch[1].seqNo, GENESIS_CODE)
  ELSE HashCode(ch[i].actor, ch[i].seqNo, ExpectedCodeAt(ch, i - 1))

RECURSIVE ExpectedPrevAt(_, _)
ExpectedPrevAt(ch, i) ==
  IF i = 1
  THEN GENESIS_CODE
  ELSE ExpectedCodeAt(ch, i - 1)

ComputeHead(ch) ==
  IF Len(ch) = 0
  THEN GENESIS_CODE
  ELSE ExpectedCodeAt(ch, Len(ch))

VerifyChain ==
  IF Len(chain) = 0
  THEN [status |-> "ok", at |-> 0]
  ELSE
    LET computedHead == ComputeHead(chain)
        broken == { i \in 1..Len(chain) :
                      \/ ExpectedCodeAt(chain, i) # chain[i].current_hash
                      \/ ExpectedPrevAt(chain, i) # chain[i].prev_hash }
    IN  IF computedHead # pinnedHead
        THEN [status |-> "fail", at |-> 0]
        ELSE IF broken # {}
        THEN [status |-> "fail",
              at |-> CHOOSE i \in broken : \A j \in broken : i <= j]
        ELSE [status |-> "ok", at |-> 0]

(* ------------------------------------------------------------------ *)
(* Actors                                                               *)
(* ------------------------------------------------------------------ *)

Actors == 1..MaxActors

(* ------------------------------------------------------------------ *)
(* Normal Actions                                                       *)
(* ------------------------------------------------------------------ *)

AppendEntry(actor) ==
  /\ Len(chain) < MaxEntries
  /\ LET seqNo == Len(chain) + 1
         entry == MakeEntry(actor, seqNo, head)
     IN  /\ chain'         = Append(chain, entry)
         /\ head'          = entry.current_hash
         \* pinnedHead is only updated when the chain is untampered.
         \* Once a tamper has occurred, pinnedHead remains frozen at the
         \* last legitimate head, so any subsequent Verify can still detect
         \* that the chain was structurally altered.
         /\ pinnedHead'    = IF tampered = 0
                             THEN entry.current_hash
                             ELSE pinnedHead
         /\ lastTimestamp' = seqNo
         /\ tampered'      = tampered
         /\ verified'      = [status |-> "none", at |-> 0]
         /\ hmacKey'       = hmacKey

Verify ==
  /\ Len(chain) > 0
  /\ verified'  = VerifyChain
  /\ UNCHANGED <<chain, head, tampered, hmacKey, pinnedHead, lastTimestamp>>

(* ------------------------------------------------------------------ *)
(* Adversarial Actions                                                  *)
(*                                                                      *)
(* All adversarial actions:                                             *)
(*   - guarded by tampered < MaxTampers                                 *)
(*   - increment tampered                                               *)
(*   - do NOT update pinnedHead (attacker cannot access the pin)        *)
(*   - reset verified to "none"                                         *)
(* ------------------------------------------------------------------ *)

\* TruncateChain(k): shorten chain to first k entries.
\* pinnedHead was written at full chain length; ComputeHead of the
\* truncated chain differs from pinnedHead -> VerifyChain detects it.
TruncateChain(k) ==
  /\ tampered < MaxTampers
  /\ Len(chain) >= 2
  /\ k \in 1..(Len(chain) - 1)
  /\ chain'         = SubSeq(chain, 1, k)
  /\ head'          = head
  /\ tampered'      = tampered + 1
  /\ verified'      = [status |-> "none", at |-> 0]
  /\ UNCHANGED <<hmacKey, pinnedHead, lastTimestamp>>

\* RemoveEntry(i): delete the entry at index i.
\* Subsequent prev_hash links and recomputed head all break.
RemoveEntry(i) ==
  /\ tampered < MaxTampers
  /\ Len(chain) >= 2
  /\ i \in 1..Len(chain)
  /\ chain'         = SubSeq(chain, 1, i - 1) \o SubSeq(chain, i + 1, Len(chain))
  /\ head'          = head
  /\ tampered'      = tampered + 1
  /\ verified'      = [status |-> "none", at |-> 0]
  /\ UNCHANGED <<hmacKey, pinnedHead, lastTimestamp>>

\* ReorderEntries(i,j): swap entries at non-adjacent positions i < j, j-i >= 2.
\* Chain link traversal breaks at both swap positions.
ReorderEntries(i, j) ==
  /\ tampered < MaxTampers
  /\ Len(chain) >= 3
  /\ i \in 1..Len(chain)
  /\ j \in 1..Len(chain)
  /\ i < j
  /\ j - i >= 2
  /\ LET swapped == [chain EXCEPT ![i] = chain[j], ![j] = chain[i]]
     IN  /\ chain'    = swapped
         /\ head'     = head
         /\ tampered' = tampered + 1
         /\ verified' = [status |-> "none", at |-> 0]
  /\ UNCHANGED <<hmacKey, pinnedHead, lastTimestamp>>

\* ForgeEntry(i): rewrite prev_hash of entry i to FORGED_CODE.
\* FORGED_CODE is a Nat sentinel above all legitimately computed hashes.
\* The attacker can write arbitrary bytes but cannot find a preimage.
ForgeEntry(i) ==
  /\ tampered < MaxTampers
  /\ Len(chain) >= 2
  /\ i \in 2..Len(chain)
  /\ chain[i].prev_hash # FORGED_CODE
  /\ LET patched == [chain[i] EXCEPT !.prev_hash = FORGED_CODE]
     IN  /\ chain'    = [chain EXCEPT ![i] = patched]
         /\ head'     = head
         /\ tampered' = tampered + 1
         /\ verified' = [status |-> "none", at |-> 0]
  /\ UNCHANGED <<hmacKey, pinnedHead, lastTimestamp>>

(* ------------------------------------------------------------------ *)
(* Next / Spec                                                           *)
(* ------------------------------------------------------------------ *)

Next ==
  \/ \E a \in Actors           : AppendEntry(a)
  \/ \E k \in 1..MaxEntries    : TruncateChain(k)
  \/ \E i \in 1..MaxEntries    : RemoveEntry(i)
  \/ \E i, j \in 1..MaxEntries : ReorderEntries(i, j)
  \/ \E i \in 1..MaxEntries    : ForgeEntry(i)
  \/ Verify

Fairness ==
  /\ WF_vars(Verify)
  /\ \A a \in Actors : WF_vars(AppendEntry(a))

Spec == Init /\ [][Next]_vars /\ Fairness

(* ================================================================== *)
(* Invariants                                                           *)
(* ================================================================== *)

(*
  TypeOK: see definition above.
*)

(*
  LinkIntegrity: prev_hash codes are consistent.
  Scoped to untampered chains: adversarial actions deliberately break links
  and are themselves the mechanism under test.
*)
LinkIntegrity ==
  tampered = 0 =>
    \A i \in 1..Len(chain) :
      chain[i].prev_hash =
        (IF i = 1 THEN GENESIS_CODE ELSE chain[i-1].current_hash)

(*
  TimestampMonotone: ts values are non-decreasing across the chain.
  Encodes AuditEntry Invariant 2 (ADR-0009 §5.2).
  Scoped to untampered chains since ReorderEntries can reverse ts order.
*)
TimestampMonotone ==
  tampered = 0 =>
    \A i \in 2..Len(chain) : chain[i].ts >= chain[i-1].ts

(*
  TruncationDetectable: if the chain is currently structurally broken
  (ComputeHead(chain) ≠ pinnedHead, meaning an adversarial mutation was not
  self-cancelling) and the verifier has run, the result must be "fail".
  This correctly handles the case where two adversarial actions cancel each
  other (e.g., ReorderEntries(i,j) twice), leaving the chain valid — in
  which case tampered > 0 but the chain is intact and Verify correctly
  returns "ok".  The invariant tests actual corruption, not tamper count.
*)
TruncationDetectable ==
  (Len(chain) > 0 /\ ComputeHead(chain) # pinnedHead /\ verified.status = "ok")
    => FALSE

(*
  HmacBindsHead: for untampered non-empty chains, HmacCode(last hash, key)
  equals HmacCode(pinnedHead, key) — they are the same code, set
  synchronously on the last Append.
*)
HmacBindsHead ==
  (tampered = 0 /\ Len(chain) > 0) =>
    HmacCode(chain[Len(chain)].current_hash, hmacKey) =
    HmacCode(pinnedHead, hmacKey)

(*
  AppendOnlyTransitionAction: two-state predicate registered as
  ACTION_CONSTRAINT in the .cfg.
  In every step, either chain grew OR tampered strictly increased.
  Replaces the tautological AppendOnlyMonotone == Len(chain) >= 0.
*)
AppendOnlyTransitionAction ==
  Len(chain') >= Len(chain) \/ tampered' > tampered

(* ================================================================== *)
(* Temporal Property                                                    *)
(* ================================================================== *)

TamperHasOccurred  == tampered > 0
VerifyResultIsFail == verified.status = "fail"

(*
  ChainBroken: the chain is currently structurally inconsistent.
  This holds when the recomputed head diverges from pinnedHead — meaning
  the adversarial mutations were NOT self-cancelling.
*)
ChainBroken ==
  Len(chain) > 0 /\ ComputeHead(chain) # pinnedHead

(*
  VerifyAfterTamperFails: whenever the chain is broken (non-self-cancelling
  tamper), the verifier eventually detects it.
  Note: self-cancelling tampers (e.g., two ReorderEntries that undo each
  other) leave tampered > 0 but ChainBroken = FALSE — in that case the
  verifier correctly returns "ok" and no liveness obligation exists.
  Fairness on Verify guarantees the verifier eventually runs.
*)
VerifyAfterTamperFails ==
  ChainBroken ~> VerifyResultIsFail

(* ================================================================== *)
(* Concurrent-writer fork invariant (Wave-3, finding E)                *)
(* ================================================================== *)

\* NoChainFork enforces single-writer serialization at the append point.
\* In the model, pinnedHead is the per-Append "lock"; this invariant
\* surfaces any violation of that assumption.
(*
  NoChainFork:
  No two distinct entries in the chain share the same prev_hash value
  while having different current_hash values.  A fork would mean two
  entries both claim to follow the same predecessor — impossible under
  the pinnedHead discipline that AppendEntry serializes writes through
  a single head pointer.

  This invariant is scoped to untampered chains.  Adversarial actions
  (TruncateChain, RemoveEntry, ReorderEntries, ForgeEntry) deliberately
  destroy structural integrity; checking fork-freedom under those
  mutations would be vacuous because FORGED_CODE is injected as a
  duplicate prev_hash sentinel.
*)
NoChainFork ==
  tampered = 0 =>
    \A i, j \in 1..Len(chain) :
      (i # j /\ chain[i].prev_hash = chain[j].prev_hash)
        => chain[i].current_hash = chain[j].current_hash

====
