# Sentinel — Elasticsearch Detection & Response Platform

Watches logs in Elasticsearch, decides when a condition holds, and does something about it.

`Sentinel` is a placeholder name; nothing depends on it.

## Where it stands

The platform runs against real infrastructure. **729 tests pass, no warnings** — including an end-to-end
suite that evaluates a rule stored in PostgreSQL against a live Elasticsearch cluster and writes the alert
it produces.

| | Built | Not yet |
| --- | --- | --- |
| **1 — Source** | Connection model, Elasticsearch adapter, connectivity probe, index and field discovery, bounded query building | — |
| **2 — Rules** | Rule and version model, two detection strategies, window planning, validation, condition builder, live preview, templates, dry run | — |
| **3 — Detection** | Alert model, deduplication, cooldown, pipeline, scheduler, checkpoints, per-rule leases, engine loop | — |
| **4 — Response** | Action contract and registry, dispatcher with retry and idempotency, three providers, per-rule payloads, safety rails, approval gate, reversal | — |
| **Feedback** | Disposition on every closed alert, per-rule false-positive rate with a verdict | — |
| **Investigation** | Cases correlated by asset, timeline, assignment, closing that resolves the alerts | Linking to a ticketing system |
| **Context** | Enrichment stage, address classification, asset inventory, severity raised by criticality | Identity, threat intel, geography |
| **Platform** | PostgreSQL schema and migrations, all stores, audit trail, cookie authentication, RBAC, write endpoints, the console, container images and Kubernetes manifests | — |

### The two processes

| | Does | Health |
| --- | --- | --- |
| `Sentinel.Engine` | Evaluates rules on a schedule and acts on what it finds. Applies migrations when `Database:MigrateOnStartup`. | `/health/live`, `/health/ready`, `/status` |
| `Sentinel.Api` | Reads the estate and discovers what a cluster holds. Composes the platform *without* the engine loop. | `/health/live`, `/health/ready` |

Separate because they scale on unrelated things: the API on how many people are reading, the engine on how
large the estate being watched is. Several API pods can run against one engine.

### What is honestly still missing

**Prometheus metrics.** Both hosts log structured events and expose health endpoints, and engines write a
heartbeat the console reads — but nothing is published in a format a scrape understands. The signals worth
alerting on are in the database and on `/status`.

**No second event source and no second notification channel.** `IEventSource` and `IActionProvider` exist
so that adding either is a class and one line of registration, but only Elasticsearch and HTTP-based
services have been built — the abstractions have not yet been tested by a second implementation.

**Three operational controls exist only as endpoints.** `POST /api/rules/{id}/run`, `POST
/api/rules/{id}/checkpoint` and the kill switch have no button in the console. The first two are a UI
gap; the kill switch is worse than that — `Safety:ActionsEnabled` is configuration, so stopping a rule
that is blocking the wrong addresses currently means editing a file and restarting the engine. For a
platform that acts on its own, that is the control most worth reaching in a hurry. (Gating an action for
approval and undoing one that already ran both exist; this is the blunt instrument that does not.)

**Enrichment reaches an inventory and nothing else.** Asset criticality and owner are looked up; identity
context, address reputation and geography are not. `IEnrichment` is the seam for them and two
implementations already use it, so a third is a class and one line — but none has been written.

**The console has no automated tests.** Every C# capability ships with one and the suite gates every
change; the browser code does not, because there is no JavaScript test harness in the repository. What
the console does has been verified by driving a real browser against a real API, which is honest
evidence and not a regression net.

The console is a dependency-free SPA served from `Sentinel.Api/wwwroot` — no build step, no framework,
three files. Sign in, connect to Elasticsearch, discover fields from the live mapping, build a condition
from rows and test it against real data before saving anything, author the actions, rehearse the whole
rule, arm it, watch alerts arrive and read the audit trail. `--reset-admin-password` on the API host is
the way back in when no account can sign in.

## The separation that matters

```
Elasticsearch → IEventSource → IDetectionStrategy → DetectionPipeline → Alert
                                                                          ↓
                              Connection ← IActionProvider ← ActionDispatcher
```

Each layer answers one question and cannot answer the next one:

- **`IEventSource`** — what happened? Only the adapter knows Elasticsearch exists.
- **`IDetectionStrategy`** — does that meet the condition? Knows nothing about SMS, addresses or accounts.
- **`DetectionPipeline`** — is this worth recording? Applies deduplication and cooldown.
- **`ActionDispatcher`** — what should be done? Owns retry, idempotency and the safety rails.
- **`IActionProvider`** — how is it done? The last layer that knows anything specific.
- **`Connection`** — which system, and with what credential? Rules never carry either.

There is no `switch` on strategy type or action type anywhere. Both resolve through a registry, so adding
either is a class and one line of registration.

## Decisions worth knowing about

**Two strategies, not five.** The brief asked for match, threshold, frequency, aggregation and time
window. Those are not five kinds of decision: threshold and frequency are one calculation with different
window semantics, aggregation is how grouping is done, and a time window is a parameter every strategy
takes. The pipeline is fixed — query, group, window — and only the predicate varies.

**Windows slide; they do not tile.** "Twenty failures in five minutes" against fixed buckets misses
nineteen at 10:04 followed by nineteen at 10:06, which is what a paced attack looks like. Consecutive
evaluations overlap, and cooldown absorbs the repetition that creates.

**Evaluation trails real time.** A log line written at 10:00:00 may not be searchable until 10:00:20.
Querying up to *now* would miss it permanently, because the window it belonged to is never looked at
again. `QueryDelaySeconds` is why, and it is the most common way a platform like this silently stops
detecting.

**Four suppression mechanisms, kept apart.** Aggregation collapses events into a detection (in the
source). Deduplication stops one evaluation being recorded twice (a unique fingerprint). Cooldown
suppresses the *next* detection for a subject (per rule *and* subject — per rule alone would let an
attacker shield every other address by tripping the rule once). Idempotency stops an action running twice
(a claimed key). Confusing any two produces a different bug.

**Structured payloads are assembled, not templated.** The brief writes them as
`{ "userId": "{{event.user.id}}" }`, which is a JSON injection: the value came out of a log line somebody
else wrote, and one containing `","admin":true` adds a field. Values are set on an object and the
serialiser escapes them. Where the author supplies the document — see *Each rule decides what its service
receives* — it is parsed into a tree *before* any value is looked at, so the shape is fixed first and a
rendered value can only ever land in a leaf.

**Dry run cannot execute anything.** Not by flag — by construction. `DryRunService` takes one dependency,
a strategy registry, and has no path to a dispatcher. A test asserts that.

**Safety rails, which the brief did not ask for.** The first time a brute-force rule runs against a
network behind NAT, the address it identifies is the office's egress address. There is a never-act list
with CIDR support, a per-rule and global cap on disruptive actions, and a kill switch that stops blocking
without stopping detection or notification.

## Writing a rule without writing a query

The loop this replaced is the reason it exists. Authoring a rule meant typing Elasticsearch DSL blind,
saving it, arming it, sending traffic and waiting — and when nothing happened the cause could equally be
the query, the threshold, the grouping, the cooldown, deduplication, or an ingest delay. Six candidates,
several minutes per attempt, and nothing to tell them apart.

**Conditions are rows, not syntax.** A field, a comparison, a value. The comparisons offered narrow to
what the field can answer once the mapping has been read — `contains` is not offered on an integer — and
the query the rows compile to is shown underneath, because it is the string that gets stored and run.
Hand-written queries stay welcome: the raw editor is a tab away, and anything expressible as rows opens
as rows when the rule is reopened, including rules written before any of this existed. A query using
`should`, or a script, is left in the raw editor rather than approximated — a builder that silently drops
the half it did not understand is worse than one that admits it.

**There is one compiler and it is on the server.** `ConditionQuery` turns rows into a query and reads one
back. The console could compile rows itself and save a round trip, and then there would be two
implementations of what a rule means — which stays true right until they differ, at which point the query
an author previewed and the query the engine runs are not the same query and nothing says so.

Values carry their type from the mapping rather than from how they look. A `term` query for `500` against
an integer field and one for `"500"` against a keyword are different queries, and guessing from the shape
of the text gets an account number written in digits wrong. Where the mapping has not been read the row
says out loud that it guessed.

**`Test condition` answers before anything is saved.** How many events matched, how they divide between
subjects, and which of those reach the threshold — in about a second, against the real cluster. One
detail in it is deliberate and looks like a bug until you know why: it asks the source for every subject
with at least one event, where the engine asks only for subjects that already cross the threshold. They
want opposite things. The engine is keeping a query cheap on a busy index; an author is trying to find
out whether twenty was the right number, and the subject sitting at fourteen is the entire answer.

It is not a dry run and does not replace one. A dry run replays the rule's own schedule and cooldown
across history and says what it *would have done*; this asks one question about one window. A subject
shown here as reaching the threshold may still have been suppressed in practice.

**The matching event is the field picker.** A real log line from the result is listed under it, flattened
to the paths a rule refers to. One click adds a condition matching that value — preferring the `.keyword`
twin when the mapping has one, because that is what an exact match needs — and another drops the field's
placeholder into whichever action field was last being typed in.

**Templates are starting points, not references.** Six of the rules people actually write, with the
condition, grouping and timings filled in and the connection and indices left to the estate. Their field
names follow ECS and will not match every index; the builder marks any row pointing at a field the
mapping does not have. None of them arrives carrying an action — a template pre-wired to block addresses
would block the wrong ones the first time somebody clicked it without reading. A test runs every template
through the same validator the save endpoint uses, because a template that cannot be saved costs more
confidence than it saves time.

`Duplicate` on an existing rule opens a copy. The second rule of any family is the first with two numbers
changed, and rebuilding it from an empty form is how estates end up with gaps rather than with rules.

### Typing a placeholder

Typing `{{` in any action field opens the vocabulary that *this* rule will carry, filtered as you type;
`Ctrl`+`Space` opens it without the braces. The list is read when the menu opens rather than captured
when the form was drawn, so changing what the rule groups by makes the new placeholder available
immediately. It is the same list the API validates against, so the menu cannot suggest something a save
would then refuse.

What gets written depends on what is already there, which is the part worth being careful about:

- A closing `}}` already typed is used, not duplicated — including the spaces of a `{{ }}` typed as a
  pair. Only a full pair is taken: a single `}` is far more likely to end the JSON object than to be
  half a placeholder, and eating it would break the body to fix a brace nobody had got wrong.
- In a **request body**, a placeholder standing where a value goes is quoted. The body is parsed as JSON
  *before* any substitution, so `"text": {{message}}` is not a template that breaks later — it is a body
  that is not JSON now. Inside a string already, no quotes are added.

The body is checked as it is typed, and the two mistakes the console can recognise are named rather than
reported as an offset: a placeholder used unquoted as a value, and braces that do not balance. Everything
else falls back to the parser's own message, where its position is genuinely useful. A body that will not
work is refused at save with the action and field named — the API refuses it too; this is the earlier and
clearer half.

## Each rule decides what its service receives

A connection says *where* to send and *how to authenticate* — including which endpoint each action calls
on it. Everything about *what* is sent belongs to the rule, because two rules pointed at one gateway
routinely need to send different things: the rule watching payments carries different facts than the one
watching a login page, and a second gateway wants different field names entirely.

That line is worth being exact about, because the endpoint sits on the wrong side of it in most tools.
The path describes the *service*: every rule pointing at one gateway calls the same endpoint on it, and
the day the gateway moves, the change belongs to the service rather than to forty rules that each wrote
the path down separately. So it is configured on the connection, keyed by action type — one security API
legitimately blocks an address at one path and suspends an account at another:

```json
{ "paths": { "block_ip": "/security/block/ip", "block_user": "/security/block/user" } }
```

Omit it and the action uses its conventional path. The console renders one field per action that could run
through a connection of that type, from the published catalogue, so a new provider appears in the
connection form without the frontend changing. A path written as a full URL is refused: the connection's
endpoint is checked against the outbound policy when it is saved, and a path allowed to carry a scheme and
host would route around that check.

### Where the platform is willing to send a request

Every outbound call this system makes is aimed by configuration somebody entered in a web form, and the
platform holds credentials and sits inside the network. That is a server-side request forgery surface by
construction: an endpoint pointed at a metadata service or a neighbouring admin port turns the connection
form into a way to reach things its author could not reach directly.

The check runs **twice, and the second time is the one that matters**. Saving a connection judges the
endpoint, which closes the obvious case and nothing else — a literal address can be read out of a URL, a
name cannot. A URL naming a host passes every check a form is able to make and then resolves to
`169.254.169.254`; worse, it can resolve to something harmless while the form is open and to the metadata
service a second later, which is the whole of DNS rebinding. So the addresses a name actually resolves to
are checked again at the moment the socket is opened, and only an allowed one is connected to.

```json
"Outbound": { "AllowPrivateNetworks": true, "AllowLoopback": false, "AllowedHosts": [] }
```

Loopback is off because in a real deployment it is the platform itself. Turn it on only where a tester
runs the service being called on the same machine as the engine — **and in both hosts**: the API judges
the endpoint when it is saved and the engine judges the address when it connects, so changing one leaves
a connection that saves cleanly and never works. A host on `AllowedHosts` is admitted past the loopback
and private-network rules and no further; the metadata addresses and link-local are refused to everyone,
because no deployment needs them and they are most of the reason this exists.

### When the certificate is not one the machine trusts

The common case, not the exception. Elasticsearch 8 auto-configures TLS with a CA it generates itself,
and the ECK operator does the same on Kubernetes — so the certificate is signed by a root nothing trusts,
and its names cover the in-cluster service rather than whatever address it is reached on. Both fail at
once: `RemoteCertificateChainErrors` and `RemoteCertificateNameMismatch`.

Three settings on the connection, ordered by how much they prove:

```json
{ "tls": { "fingerprint": "5F:5A:…" } }                        // pin this exact certificate
{ "tls": { "caCertificate": "-----BEGIN CERTIFICATE-----…" } }  // verify against a private root
{ "tls": { "allowInvalidCertificates": true } }                 // verify nothing
```

**Pinning is usually the one that helps**, and it is not the weakest of the three — it answers a different
and stronger question. "Is this exactly the certificate I was told to expect" needs neither a trusted
issuer nor a matching name, which is why it works where the address is not on the certificate. Elasticsearch
prints the fingerprint on first start and Elastic's own clients call it `ssl_assert_fingerprint`.

**A supplied CA replaces the trusted roots and nothing else.** The name is still checked, so it is full
verification against a private root rather than an exemption — a test asserts it still refuses a mismatched
name.

**Accepting any certificate trusts whatever answers on that address** with the connection's credentials.
It is there because it is sometimes the only way to make progress; the console marks the connection
`certificate not verified` wherever it appears, and the engine says so in its log on every start.

Getting the fingerprint, from anywhere that can reach the cluster:

```bash
openssl s_client -connect <host>:<port> </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout
```

An SMS action has two settings, and the split between them is the whole design:

| | |
|---|---|
| **Message** | The sentence a person reads. Placeholders are filled from the alert. |
| **Request body** | The JSON the gateway expects. Optional — leave it empty and the platform sends its own body. |

```json
{
  "to": "+989121234567",
  "text": "{{message}}",
  "unicode": false,
  "alert": {
    "id": "{{alert.id}}",
    "api": "{{event.ApiName.keyword}}",
    "errors": "{{evidence.eventCount}}",
    "window": "{{evidence.window}}"
  },
  "lastEvent": {
    "at": "{{sample.@timestamp}}",
    "user": "{{sample.UserID}}",
    "sourceIp": "{{sample.SourceIP}}",
    "raw": "{{sample.message}}"
  }
}
```

`{{message}}` is the rendered Message, so the sentence is written once and placed in whichever field the
gateway calls it. Nesting and arrays work. **Literals keep the type the author wrote** — `false` is a
boolean, `3` is a number — but a placeholder always renders as a string, even when the value looks
numeric. Inferring the type from the rendered text is how an account id of `"0071"` becomes `71`; a
gateway that wanted a number and got a string answers 400, which is a failure somebody can see and fix.

### What a rule can reference

Computed from the rule, not published as one fixed list, because most of it depends on the rule:

| Path | From |
|---|---|
| `{{subject}}` | What the alert is about, whatever this rule groups by |
| `{{message}}` | The rendered Message, inside a payload |
| `{{alert.id}}` `{{alert.severity}}` `{{alert.timestamp}}` | The alert |
| `{{rule.id}}` `{{rule.name}}` `{{rule.version}}` | The rule version that fired |
| `{{event.<field>}}` | The fields the rule groups by |
| `{{sample.<field>}}` | The log line itself — one of the events behind the alert |
| `{{actions.<type>.status}}` `.reason` `.target` | What an action **earlier in this rule** did |
| `{{evidence.<name>}}` | Declared by the strategy — a threshold rule has `eventCount`, `threshold`, `window`, `windowFrom`, `windowTo`, `groupBy`; a match rule has `matchedEvent` and no count |

The console offers exactly these as clickable chips, and the API refuses a rule that references anything
else. Both read the same list, from `RuleVocabulary`, so what is offered and what is accepted cannot
drift. A strategy declares its own evidence names — `IDetectionStrategy.EvidenceKeys` — and a test asserts
the declaration matches what evaluation actually produces.

**`event.` and `sample.` are not the same thing, and the distinction matters.** `event.` is the subject —
what the rule grouped by — and it is true of every event in the group. `sample.` is one event out of
fourteen, the most recent in the window, and its fields describe that line only. Both belong in a message;
confusing them produces one that reads as though it described all of them.

The sample is what makes an alert say *what* happened rather than only that something did:

```
HIGH: ExtServices returned 14 HTTP 500s in 5m.
Last: ext1@carbon.super on /ExtServices/v2/lookup from 192.168.8.61.
```

It costs no extra round trip — it arrives as a `top_hits` sub-aggregation inside the query that already
counts, so a rule with forty qualifying subjects still makes one request. It is stored on the alert as
well as handed to the actions, because an SMS reading "see alert 41" is worth little if alert 41 cannot
then show the line that caused it.

Which fields a sample carries is not knowable until an alert is raised, and two documents in one index
need not agree — so `sample.*` is accepted without the platform pretending to know the mapping. The rule
builder fills the list in from the connection's real mapping, which it has already discovered by the time
an author is writing a message.

### A message that can say what the block did

An alert's actions run in order, so that "block the address, then tell somebody it was blocked" happens in
that order. `{{actions.<type>.status}}` is what makes the second half honest:

```
CRITICAL: 12 failed sign-ins from 192.168.9.22 in 5m.
Block: SKIPPED. '192.168.9.22' is on the never-act list.
```

Without it a rule could only assert. A message reading "Address blocked." said so whether or not the
address had been blocked — and the case where it is wrong is precisely the case that matters, because the
never-block list fires on the estate's own addresses.

An action sees the actions **before** it and not the ones after, and the API enforces that per action
rather than per rule: referring forwards would render a blank on every alert, on the one rule somebody was
relying on. `.reason` carries the explanation, because `SKIPPED` alone does not distinguish a protected
address from a switched-off gateway, and those want different responses from whoever reads the message.

**An action that was deliberately not carried out is recorded**, with its reason, and appears on the
Actions page like any other. It has to be: "no block happened" and "a block was withheld because the
address is on the never-block list" look identical otherwise, and the second is a decision somebody needs
to be able to find afterwards.

### Held until somebody says yes

Any action on any rule can be gated. The rule still fires and the alert is still raised; that action is
claimed and parked as `PENDING_APPROVAL` instead of happening, and there is **no path from a held action
to an executed one that does not pass through a person** — the dispatcher does not call the provider at
all on that branch.

Claimed rather than merely noted, so the gate cannot become a second way to run the action: a node
reaching the same alert afterwards finds the key already owned. And the actions after it can read
`{{actions.block_ip.status}}`, so the message that goes out says what is true —

```
CRITICAL: 37 slow responses from Payments in 5m.
Block of Payments is PENDING_APPROVAL. Held for approval until 17:32Z. It has not been carried out.
```

Unanswered, it expires. `Safety:ApprovalWindowSeconds` decides how long, floored at a minute, and the
engine sweeps on every tick. That direction is deliberate: an approval that waits indefinitely is not a
gate but a queue nobody empties, and saying yes the next morning blocks an address over a situation that
ended hours ago.

Approving rebuilds the request from the alert and the **rule version that produced it** rather than from
anything stored when it parked — so it sends exactly what would have been sent an hour ago, even if the
rule has been edited twice since.

### Taking one back

`block_ip` and `block_user` implement `IReversibleAction`; `sms` does not, because a message that reached
somebody's phone cannot be unsent. A platform that blocks addresses on its own and cannot unblock one is
not automation with a safety rail — it is a decision nobody can revisit, and the occasions an automated
block is wrong are exactly the occasions somebody needs it lifted within the minute. Expiry through the
gateway is not the same thing: that is a promise made by a system this one does not control, on a schedule
nobody here can shorten.

A reversal is its own act with its own idempotency key, and it is recorded **on** the original rather than
replacing it. What the platform did at three in the morning happened; a record the person undoing it at
nine could rewrite would answer "which addresses did we block last night" with a lie. The undo endpoint is
configured like any other: `{"paths": {"block_ip.reverse": "/firewall/v2/allow"}}`.

The Actions page says how many automated changes are still in force, because that is the question people
ask during an incident.

### Checked when it is saved, not when it fires

Every action binding is validated against the provider that will run it and the connection it will run
through: the body must be a JSON object, the placeholders must be ones this rule produces, the connection
must exist, be enabled, and be of the type the action needs. A Block IP action reading `event.source.ip`
on a rule grouped by `SourceIP.keyword` is refused too — otherwise the rule saves, arms, raises alerts,
and reports `NO_TARGET` forever.

This matters more than ordinary form validation. The alternative is a rule that looks armed and healthy
until the night it was written for, and then sends a message with a blank where the address should be.

### When the cluster refuses

`search_phase_execution_exception: Partial shards failure` is true and useless — it says some shard
refused without saying which or why, and a rule failing on it thirty times gives an operator nothing to
act on. The cause sits one level down in `failed_shards`, and it usually names both the index and the
mapping that disagrees with the query, so it is carried out:

```
search_phase_execution_exception: Partial shards failure — query_shard_exception:
failed to create query: For input string: "n/a" (index wso2_2026-05-23)
```

Only the first failure is reported. A pattern spanning three hundred daily indices reports the same
conflict three hundred times, and a message that repeats itself is one nobody reads to the end; the first
names an index, which is enough to go and look.

Queries are sent with `allow_partial_search_results=false` deliberately. A detection that silently saw
part of the cluster and reported nothing is worse than one that failed and retried.

### What the execution record shows

The stored summary of every call is redacted: `recipients`, `to`, `mobile`, `msisdn`, `phone`,
`phoneNumber`, plus anything named in the action's **Hide from the log** setting. Once the body is the
author's to shape the platform can no longer know which field holds a number, and an execution record is
read by more people than are entitled to the security team's phone numbers. Redaction applies to the
record, never to the request — the gateway still gets the number.

### Trying it without a real service

`samples/ServiceStub` is a real receiver that records what it was sent. It answers on the endpoints all
three actions call, so one program stands in for any of them:

```bash
STUB_NAME="sms gateway"  dotnet run --project samples/ServiceStub -- --urls http://0.0.0.0:9310
STUB_NAME="security api" dotnet run --project samples/ServiceStub -- --urls http://0.0.0.0:9320
```

Two instances, because two services is the case worth rehearsing: a rule that blocks an address *and*
tells somebody has to reach two systems, and "it called something" is not the same as "it called the right
one". Point a connection at each, arm a rule, and read `GET /received` for the exact documents that left
the platform, or `GET /received/count` for the tally per endpoint.

`/fail` answers 500 and `/reject` answers 400, so retry, backoff and dead-lettering can be rehearsed
against something that actually refuses — a platform only ever tested against a service that says yes has
never exercised any of them.

## Deploying it

`deploy/README.md` is the whole procedure: provisioning the database and its role, building the two
images, the Secret and the ConfigMap, the migration Job, and what to check before arming anything. The
manifests are in `deploy/kubernetes/`.

Three things there are worth knowing before the first deploy, because each was a silent failure until it
was fixed:

- **The session key ring lives in the database.** ASP.NET Core builds one per process, so two API replicas
  would sign cookies with different keys and everyone would be signed out whenever the load balancer sent
  them to the other pod. Without this the API could not honestly run more than one replica.
- **Engines write a heartbeat.** The console used to read the tick interval and the never-act list out of
  the *API's* configuration — and the API evaluates nothing and blocks nothing, so a crashed engine looked
  exactly like a healthy platform with nothing to report.
- **`Hosting:TrustedProxies` decides whether X-Forwarded-For is believed.** Until it names the ingress's
  network the audit trail records the proxy rather than the person; trusting the header unconditionally
  would let a caller write any address they liked into it.

## Running it

```bash
export ConnectionStrings__Sentinel="Host=…;Port=5432;Database=sentinel;Username=…;Password=…"
export Secrets__Key="$(head -c 32 /dev/urandom | base64)"

dotnet run --project src/Sentinel.Engine -- --migrate   # apply the schema and stop

dotnet run --project src/Sentinel.Engine    # evaluation
dotnet run --project src/Sentinel.Api       # reading
```

`--migrate` applies the schema and exits without starting the evaluation loop — the same command the
Kubernetes Job runs, from the same image. Applying the schema is then one thing that happens once, at a
moment somebody chose, rather than a side effect of whichever replica started first. `dotnet ef database
update` still works for local iteration.

The EF tooling reads `SENTINEL_CONNECTION` at design time; the hosts read `ConnectionStrings:Sentinel`.
Neither is ever committed.

## Testing

```bash
dotnet test Sentinel.slnx
```

729 tests and no external dependencies. Elasticsearch and the security API are recorded HTTP handlers and
the database is SQLite, so the suite needs neither a cluster nor a server. The exceptions are the tests
that could not prove anything against a fake: TLS verification runs a real handshake against a real
self-signed certificate on a loopback listener, and the outbound address guard opens real sockets —
a recorded handler never connects, so it could not tell a guard that works from a comment saying one does.

Setting two variables adds 11 more that talk to real servers — genuine write concurrency against one
unique index, the migration matching the model, and a rule in the database becoming an alert from live
events:

```bash
export SENTINEL_CONNECTION="Host=…;Database=sentinel;Username=…;Password=…"
export SENTINEL_ES="http://…:9200"
```

They clean up after themselves by prefix, and never dispatch an action: a test that blocked an address to
prove it could would be exactly the accident the safety rails exist to prevent.

`AcceptanceTests` runs the brief's end-to-end scenario with every layer real except those two edges.
`CompositionTests` builds the container with `ValidateOnBuild` and `ValidateScopes`, which is what catches
a singleton holding a scoped `DbContext` — a bug that otherwise appears only under load, weeks later.

## What the estate knows about the subject

Between detecting and responding there is now a step that asks what the platform already knows about the
thing an alert is about. It existed because every decision after detection — how serious this is, whether
to block — was being made from the grouped fields and one sample event alone, and "block 10.5.5.5" is a
different decision depending on whether that address is a laptop or a domain controller.

Enrichments run after cooldown and deduplication and **before the alert is written**, so what they found
is part of the record rather than something attached afterwards, and a suppressed candidate costs no
lookups. They reach the actions as `{{enrich.asset.owner}}`.

Two ship, so the abstraction is exercised by more than one implementation:

| | |
|---|---|
| `network` | Classifies the address — private, public, loopback, link-local — and says whether the never-act list protects it. Needs no configuration, so every deployment gets something. |
| `asset` | What the inventory says: name, criticality, owner, environment. An exact entry beats a range containing it, and the narrowest range wins. |

The fact that earns `network` its place is `protected`. The never-act list is consulted by the dispatcher
at the moment it refuses to block, which is *after* the message has gone out saying an address was
blocked. Known here, a rule's own message can say the address is protected and will not be blocked.

**Severity is raised, never lowered.** A critical asset argues for a floor; the pipeline takes the higher
of the two. The asymmetry is the point: an enrichment able to lower severity would let a stale inventory
entry quietly downgrade a real incident, and nothing about the alert would look wrong afterwards. Only the
top two criticalities raise anything — a floor at "normal" would raise every alert in the platform, which
is the same as raising none.

```
[CRITICAL] ApplicationName.keyword=AiServices — AI services gateway, owned by Platform team (production)
[LOW]      ApplicationName.keyword=Payments — , owned by  ()
```

Two alerts from one rule that says `LOW`. The estate knows something about the first subject and nothing
about the second, and neither message invents anything.

**An enrichment that fails cannot cost the alert.** These reach inventories and third-party services —
things that are down at exactly the moment an incident is happening. A failure is bounded at five seconds,
logged, recorded as `enrich.<name>.error`, and the alert proceeds. Recorded rather than only logged,
because the person reading the alert is not reading the engine's log and "owner: " with no explanation is
indistinguishable from an asset nobody has entered.

The inventory is deliberately small: an identifier, a kind, a name, a criticality, an owner. Not a CMDB
and not trying to be one — what the platform needs before it acts is whether this matters and who to ask.

## One investigation, not twelve alerts

The unit an analyst works in is not an alert. Twelve alerts about one host in ten minutes are one question,
and answering it twelve times — closing twelve rows — is the toil that makes people stop reading alerts.

Cases were built after disposition and enrichment, and the order is the point. Without a disposition there
is nothing to close a case *with*; without enrichment two alerts about one machine look like two unrelated
subjects. Grouping before either exists only tidies the noise.

**Correlation is one sentence: the asset if the enrichment found one, otherwise the subject.** Anything
cleverer — scoring, graphs, transitive association — produces cases whose membership nobody can explain,
and a case an analyst cannot explain is one they stop trusting. The asset comes first because it is what
makes grouping work across rules that see one machine differently, which is visible in the output:

```
CASE-…-A13D06  AI services gateway              CRITICAL  2 alerts   ← two rules, one asset, one case
CASE-…-905158  ApplicationName.keyword=Payments MEDIUM    1 alert    ← no asset entry, so
CASE-…-B8836A  ApiName.keyword=Payments         MEDIUM    1 alert       two rules look like two subjects
```

Both halves are the same two rules firing on the same two hosts. The inventory has an entry for one of
them and not the other, and that is the whole difference.

**At most one open case per entity, as a database constraint.** The third guarantee in the platform that
is an index rather than logic: `cases.OpenKey` is the entity while open and null once closed, and nulls do
not collide. Two engine nodes raising alerts about one host in the same instant would otherwise both find
nothing and both open a case, with an analyst reading half the story in each.

**A case ends when somebody ends it.** There was a time window here — an alert hours later starting a
fresh case — and writing the test removed it: it contradicted the constraint beside it. Both can hold only
if the platform closes the old case, and concluding an investigation is a judgement. A case that has been
collecting alerts all week is a true statement about the queue not being worked, and splitting it
automatically would hide that.

**Closing a case closes its alerts**, with the disposition recorded once. That is the payback for having
cases at all.

The timeline is ordered by identity rather than timestamp. Rules evaluate concurrently and each captures
its own clock reading before touching the database, so the alert that opened a case can carry a timestamp
a microsecond later than one that joined immediately after — and the timeline then claims the alert was
added before the case existed.

## Whether a rule is worth keeping

Closing an alert asks what it turned out to be, and the field is required — one people may skip is one
that is empty on most rows, and a rate computed from a quarter of the alerts is worse than none because
it looks authoritative.

Four values, not two. `FALSE_POSITIVE` is the only one counted against the rule: a backup job that trips
a detection every Sunday is `BENIGN` — the rule was right and the activity was authorised, and what wants
fixing is an exception rather than the logic. Counting those as failures condemns rules that are working.

```
FALSE_POSITIVE / judged alerts      > 20% — worth an hour
                                    > 50% — costing more attention than it saves
```

The denominator is alerts somebody has judged, not all of them: otherwise a rule looks better the more of
its alerts are ignored. And a verdict needs five judged alerts before it is given at all, because one
wrong alert out of one is not a 100% failure rate — it is one alert, and reporting it as the former is how
a good rule gets deleted in its first week.

An armed rule that has never fired is called out separately. Silence reads as peace and is usually a
broken log source, and nobody goes looking for a rule that is not complaining.

## Guarantees that are constraints, not code

Two of the platform's promises are database indexes rather than logic, and this is deliberate:

| Promise | Mechanism |
| --- | --- |
| One detection produces one alert | unique index on `alerts.fingerprint` |
| One alert blocks an address once | unique index on `action_executions.idempotency_key` |

Both are attempted-then-caught rather than checked-then-written. A check followed by a write races between
nodes: both callers find nothing, both insert, and one detection becomes two blocks. Letting the insert
fail turns the race into an answer.

This is why the tests run against SQLite rather than EF Core's in-memory provider — that provider ignores
unique indexes, so these tests would have asserted nothing while appearing to pass.

## Running as more than one pod

Rules are leased individually rather than through a single leader. A leader would leave every other node
idle and cap throughput at one machine; per-rule leases spread the work and still guarantee that two nodes
never evaluate one rule at once. Leases expire rather than being released, so a node that dies
mid-evaluation does not hold its rules until somebody notices.

A checkpoint advances only after a window has actually been evaluated. A failed run leaves it where it
was — a failure has examined nothing it can vouch for, and moving past those windows would lose them with
no trace.

The API side of the same question is the session key ring. It lives in the database rather than on each
pod, because ASP.NET Core builds one per process: two replicas would sign cookies with different keys, and
a session would survive exactly as long as the load balancer kept sending that person to the same pod.

## What to build next

Ordered by what would be missed most, which is not the same as what is most interesting to build.

1. **The kill switch, as a control rather than a setting.** Stopping actions means editing
   `Safety:ActionsEnabled` and restarting the engine. The console shows whether actions are enabled — it
   reads the engines' heartbeats — but cannot turn them off. A request shape for it is already declared
   and nothing maps it. Of everything on this list it is the only one somebody might need in the next
   sixty seconds.

2. **Run now, and reset the checkpoint.** Both endpoints exist, tested, with no button. The second is the
   one that costs hours: when a rule's window has moved past the events being tested, there is no way to
   move it back from the console.

3. **Version history in the console.** `GET /api/rules/{id}` already returns every version with its
   author and change note. The rule form even asks "what changed" and then shows it nowhere.

4. **A second event source.** `IEventSource` exists so the engine's question — "does this condition hold"
   — stays answerable without knowing that the answer currently comes from Elasticsearch. That claim is
   untested until something else implements it.

5. **A second notification channel.** Email, Slack, a webhook. The action registry and the per-rule payload
   already make this a class and one line of registration, and the SMS provider's shape — a message, a
   body the rule defines, an endpoint the connection names — is the shape a second one would take.

6. **Prometheus metrics.** Engines write a heartbeat and the console reads it, so "is it running" is
   answered; what is missing is a scrape format, so the same question can wake somebody at night. The
   signals are already there: nodes that stopped reporting, rules with consecutive failures, actions in
   `DEAD_LETTER`.

7. **Alert routing.** Every rule names its own actions today, which is right for a small estate and
   repetitive for a large one — forty rules that all page the same team repeat the same binding forty
   times. A rule would name a severity and a route would decide who hears about it.
