# What leaves a session

Status: design, partly built. Milestone 1 built the schema, its encoder and
a session image with no console. A guest's end code, logs for the owner,
statistics and events, review, and a schema for the key service's answers
are not built yet. [sessions.md](sessions.md) is the overview.

A confidential session keeps the host out, but its guest still speaks to the
world outside its TD. It answers the daemon, reports its phases, writes logs,
can crash, and, on a platform that enforces rules of use, says whether a
session broke them. Each of these is a way out, so none is left to chance:
this document fixes what a guest may say in plaintext, and how a platform
enforces its rules without reading a session.

## Rules

1. **Plaintext leaves by schema only.** Every message the guest itself sends
   in plaintext beyond the boundary, to the daemon, the platform or a
   console, has a type in its image's disclosure schema, and every field of a
   type is bounded: a code from a list, a flag, a counter, a size, a time or
   a digest, or evidence and documents that are public by design. Everything
   else leaves encrypted, to the owner or to a peer whose evidence the guest
   has verified. What the session sends where its egress policy allows is
   its own, and the policy can require TLS everywhere.
2. **No free text.** No field holds a string the session can choose, so no
   error message, path, host name or stack trace leaves in plaintext. A
   refusal or a crash is a code.
3. **The schema is part of the image.** The build writes it from the agent
   itself onto the image's verity root, so the measurements cover it, and
   publishes it beside the image's manifest and with its reference values in
   the release log ([Releases](sessions.md#releases)). The agent ends a guest
   whose copy differs from the schema compiled into it, and a guest that said
   more would be another image.
4. **One encoder.** The agent writes every plaintext message through one
   encoder, which checks it against the schema as it is written and holds
   back whatever does not fit. The sandbox has no path to the host but the
   gateways, so nothing in it can add to what the guest says.

The schema does not cover answers on routes that need a key the bind grants,
once the guest has accepted the key: they travel only inside the TLS channel
that ends in the guest, to that key's holder, and the host sees only their
sizes and timing. A refusal before the key is accepted goes through the
encoder like any other answer. Nor does the schema cover the HTTP library's
fixed refusal of a malformed request, what firmware and the boot stub print
before the kernel runs, or the key service's answers, which will get a
schema of their own. None of these lets a session put plaintext of its
choosing where the host can read it.

## What the host sees

| From | What leaves in plaintext | Bounded by |
|---|---|---|
| the TD as a VM | that it runs, its class, its memory high-water mark, and when it ends | the hardware; this is metadata |
| the network | sizes, times and endpoints of ciphertext | metadata ([non-goals](session-threat-model.md#goals)) |
| answers to the daemon | phases; a bind taken, or a refusal code; a commit's or a seal's generation, and its layers' ids and sizes; each epoch's generation and its record's size class; whether a restore brought processes back | the schema |
| events and statistics | VM-level counters, sizes and times | the schema |
| evidence | certificates, documents, events and quotes | public by design |
| a console | nothing once the kernel runs; before that, what a release build of the firmware and the boot stub print, before any session exists | the image ([Logs](#logs-consoles-and-crashes)) |
| review | a policy's signals, on its schedule, within its budget | [Private review](#private-review) |
| the session's own traffic | what it sends where its egress policy allows | the owner's policy |

## Logs, consoles and crashes

- **No console.** A session image's kernel is built without a console the
  host could read (no virtual terminals, virtio console, netconsole or early
  printk), with a null console as its default, and the agent and the key
  service check that no console but the null one is registered before they
  serve. Boot's progress reaches the host only as phases from the schema.
  A debug build keeps a console, at other measurements, which no verifier of
  real sessions accepts.
- **Logs stay in the session.** The agent's, the sandbox's and the kernel's
  logs are written inside the TD, kept with the session's state and sealed
  with it, and read by the owner over the attested channel.
- **A crash leaves a code.** A guest that fails ends with a reason from the
  schema, such as lease lost, bind refused, out of memory or a kernel fault.
  Nothing of its memory leaves: the host cannot read a TD's private memory,
  and the guest writes no dump outside it.
- **Support goes through the owner.** An operator who needs to see inside a
  session asks its owner, whose client can open the session's logs and share
  what it chooses. No call or key lets the platform look in alone.

## Private review

A platform that hosts agents has rules of use, and it is held to them: it
must find the sessions that break them and act. A confidential session gives
it nothing to read. Private review lets it check every session against its
rules, inside the session, and learn only verdicts, within limits the owner
can read before any secret enters.

- **Review runs in the session's TD.** A review policy names a reviewer, a
  measured program that the guest runs beside its gateways, and the
  classifiers it may call, which it reaches only through the inference
  gateway and so only on attested inference. The reviewer reads what passes
  the gateways as it passes: model calls and their answers, egress, and
  outgoing envelopes.
- **Nothing is kept for later.** Content is reviewed as it passes and stored
  nowhere for review, so there is no store of sessions' content, in plaintext
  or waiting for a reviewer's key, to be breached or misused.
- **Only signals leave.** A policy declares a signal schema of a few fields,
  each a code from a short list, such as a category and an action. A signal
  leaves through the disclosure encoder like any plaintext, so one signal can
  say no more than its schema allows: a few bits.
- **Actions are listed.** A policy may also stop an effect inside the TD,
  such as a model call. A stop shows in the session's traffic, so the policy
  lists the actions it may take, and each one counts against the budget like
  a signal.
- **A budget per session.** A policy sets how many signals and actions a
  session may cost in a day and over its life. The key service keeps what
  each session has spent, in the session's record, and the guest spends by
  compare-and-swap before a signal leaves or an action is taken, so neither a
  restore of an older seal, nor a fork, nor a second TD can spend it again.
  All that review can ever reveal about a session is its budget's worth of
  signals and actions, each with its fields and the interval it fell in. When
  the budget is spent, the last signal says so, and what follows is the
  platform's rule, such as ending the session, which a platform can always
  do.
- **On a fixed schedule.** Signals leave in batches at fixed intervals that
  the policy sets, each batch padded to one size and encrypted to the
  platform's review key. The host learns nothing from them, and the platform
  learns from their timing only the interval.
- **One policy per class.** A review policy applies to every session of a
  class, comes only from the release log, and is named by its digest in each
  bind, so it is in the session's evidence. A session reviewed under another
  policy than its class's shows it to its owner, and a class made for a few
  users shows up in the public log.
- **Receipts.** Each spend from a budget is an entry in the key service's
  ledger, so an owner can list every signal and action about its sessions,
  each with an inclusion proof, as it lists releases and seals. Whether the
  owner sees a signal's fields at once or after a delay is part of the
  policy, and so is public too.
- **Optional.** Review is the platform's choice per class. A class without a
  review policy sends no signals at all.

## What the evidence shows

From one session's evidence a verifier reads the digest of the image's
disclosure schema, and the session's review policy, with its signal schema,
actions, budget and schedule, or that it has none, each with an inclusion
proof from the release log. So an owner's client can show, before any secret
enters, everything the session can ever say in plaintext, and to whom.

## Open questions

1. **Budgets and signal schemas**: how many signals a day and over a life a
   platform's rules need, and how few fields serve them.
2. **Duties beyond a signal**: how a platform meets an obligation that asks
   more of it than a signal, with no way to read a session.
3. **Logs after a crash**: whether a dead TD's last logs should be kept,
   sealed to its owner.
