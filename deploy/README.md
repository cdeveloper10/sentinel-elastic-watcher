# Deploying Sentinel

Two processes, one database, one Elasticsearch cluster.

| | Runs | Scales on |
|---|---|---|
| `sentinel-api` | The console and the REST API | How many people are reading |
| `sentinel-engine` | Evaluates rules on a schedule and acts on what it finds | How large the estate being watched is |

They share nothing but the database, which is why they scale separately.

---

## 1. The database and its role

Sentinel owns one PostgreSQL database and connects as one role. Neither is created by the platform:
creating databases and roles needs privileges the running service must not hold, and an account that can
`CREATE DATABASE` can also drop one.

Run these once, as a superuser, in this order.

```
psql -h <host> -p <port> -U postgres -d postgres \
     -v app_password="'<generated>'" -f provision-database.sql

psql -h <host> -p <port> -U postgres -d sentinel_prod -f provision-schema.sql
```

Generate the password rather than choosing one — it is typed nowhere, only pasted into a Secret:

```
openssl rand -base64 24 | tr -d '/+=' | head -c 28
```

### Who owns the tables

`sentinel_app` must own them, not merely be able to read them, because migrations create and alter tables.
If the schema is applied by a different role — a superuser during setup, say — the tables belong to that
role and the application can then connect and do nothing.

Applying it as the wrong role and repairing it afterwards is avoidable: authenticate as whoever the server
allows and drop into the application role for the session, so every object is created with the right owner
in the first place.

```
Host=...;Database=sentinel_prod;Username=postgres;Password=...;Options=-c role=sentinel_app
```

`SET ROLE` also drops superuser for the session, so a migration run this way has exactly the privileges
the application will have — which is the point. Check afterwards:

```sql
SELECT tablename, tableowner FROM pg_tables WHERE schemaname = 'public';
```

### The server has to let the role in

Creating a role is not the same as being able to authenticate as one. PostgreSQL decides that in
`pg_hba.conf`, which no SQL statement can change, so a freshly created role is refused with
`no pg_hba.conf entry for host ..., user ..., database ...` until a line is added:

```
host    sentinel_prod    sentinel_app    <the address Sentinel connects from>/32    scram-sha-256
```

then `SELECT pg_reload_conf();`. Check the file parsed before trusting it — a malformed `pg_hba.conf` is
kept out of service on reload and refuses to let the server start on the next restart:

```sql
SELECT line_number, error FROM pg_hba_file_rules WHERE error IS NOT NULL;
```

Note which address. If clients reach the database through a proxy or a connection pooler, the server sees
the proxy's address and every application on that path arrives as the same host — so a rule written for
one of them admits all of them.

---

## 2. Images

One Dockerfile, two targets. Everything below the two hosts is shared, so they build together and only the
final layer differs.

```bash
docker build --target api    -t sentinel/api:1.0.0    .
docker build --target engine -t sentinel/engine:1.0.0 .
```

Both run as uid 64198, non-root, with a read-only root filesystem and no capabilities. Neither contains
the test project or `samples/ServiceStub` — the sample receiver accepts anything and authenticates nobody,
and has no business in a cluster.

---

## 3. The secret

Two values, and losing each has a different consequence.

| | |
|---|---|
| `ConnectionStrings__Sentinel` | Where the platform's own state lives |
| `Secrets__Key` | 32 bytes of base64 that encrypt every credential stored against a connection |

```bash
head -c 32 /dev/urandom | base64
```

Lose the key and every connection has to be re-entered — the Elasticsearch password, the SMS gateway's API
key, the security API's token. Leak it and whoever has it can decrypt all of them from a database dump.
**Rotating it** means moving the current value into `Secrets__PreviousKeys` *before* setting a new
`Secrets__Key`; deploy a new key without that and every stored credential becomes unreadable at once.

`kubernetes/02-secret.example.yaml` shows the shape. Fill it in from wherever the estate keeps secrets —
External Secrets, Vault, sealed-secrets — rather than committing the result.

---

## 4. Fill in the safety rails before arming anything

`kubernetes/03-config.yaml`, and this is the field to read twice:

```yaml
Safety__NeverBlockAddresses__0: "10.0.0.0/8"
```

The first time a brute-force rule runs against a network behind NAT, the address it identifies is the
office's egress address, and blocking it takes the whole company off the internet. These are the ranges
the platform refuses to act on however convincing the evidence. The dashboard warns while the list is
empty; that warning is not decoration.

`Hosting__TrustedProxies` is the other one. Until it names the ingress controller's network, the audit
trail records the socket address — which behind an ingress is the ingress pod, so every entry names the
proxy rather than the person. `X-Forwarded-For` is honoured only from the networks listed there, because a
header anyone can set is not evidence.

Both hosts read the same ConfigMap deliberately: the engine enforces the safety rails and the API reports
them, and a deployment that configured them on one and not the other used to show a console promising
protection nobody was enforcing. The dashboard now says so out loud when the engines disagree.

---

## 5. Deploy

The migration runs first, as a Job, and must finish before either Deployment starts. It is idempotent —
"the schema is up to date" and exit 0 when there is nothing to apply — so it is safe on every deploy.

```bash
kubectl apply -f kubernetes/00-namespace.yaml
kubectl -n sentinel apply -f kubernetes/02-secret.yaml     # your filled-in copy
kubectl -n sentinel apply -f kubernetes/03-config.yaml

kubectl -n sentinel apply -f kubernetes/04-migrate-job.yaml
kubectl -n sentinel wait --for=condition=complete job/sentinel-migrate-1-0-0 --timeout=5m

kubectl -n sentinel apply -f kubernetes/01-serviceaccount.yaml
kubectl -n sentinel apply -f kubernetes/05-api.yaml
kubectl -n sentinel apply -f kubernetes/06-engine.yaml
kubectl -n sentinel apply -f kubernetes/07-networkpolicy.yaml
kubectl -n sentinel apply -f kubernetes/08-ingress.yaml    # your filled-in copy
```

With Helm or Argo the Job is a pre-upgrade hook or an earlier sync wave. `kustomization.yaml` builds
everything except the two examples, but kustomize does not order applies — wait for the Job yourself.

### The first administrator

Printed once, in the API's log, on the first start against an empty database:

```bash
kubectl -n sentinel logs deploy/sentinel-api | grep -A 3 "First run"
```

Sign in and change it. A platform that ships with a known default password is a platform with no password,
and this one can block traffic.

Locked out later — no usable account, a lost password:

```bash
kubectl -n sentinel exec deploy/sentinel-api -- dotnet Sentinel.Api.dll --reset-admin-password
```

It re-enables the account and restores the Admin role as well as setting a password, because the situation
it exists for is "nobody can administer the platform", and fixing only the password would leave a disabled
account still unable to sign in. It prints once and exits without serving; there must already be at least
one account, so start the API normally once before reaching for it.

### Reach the console over HTTPS, or you cannot sign in

Outside Development the session cookie is issued `secure`:

```
Set-Cookie: sentinel.session=…; path=/; secure; samesite=lax; httponly
```

Browsers accept a `secure` cookie over plain HTTP **only on `localhost`**. Reached on
`http://10.0.0.5:8080`, the sign-in request succeeds with 200, the browser discards the cookie, the next
request is 401 and the console shows the sign-in form again — with no error anywhere, because nothing
failed. The session was simply never stored.

That is the intended behaviour: a session cookie for a console that can block network traffic must not
travel in the clear. Terminate TLS at the ingress. To look at it quickly without one, come in on
localhost:

```bash
kubectl -n sentinel port-forward deploy/sentinel-api 8080:8080
```

`ASPNETCORE_ENVIRONMENT=Development` relaxes the policy to `SameAsRequest` and belongs on a laptop, never
on a cluster.

---

## 6. Check it is actually running

The dashboard answers this, and it is worth knowing why that took work. It used to read the engine's tick
interval and the never-act list out of the *API's* configuration — and the API evaluates nothing and blocks
nothing, so a crashed engine looked exactly like a healthy platform with nothing to report. Engines now
write a heartbeat after every tick and the console reads that.

```bash
kubectl -n sentinel get pods
kubectl -n sentinel port-forward svc/sentinel-api 8080:80
```

On the dashboard: each engine by name, when it last completed a tick, what it evaluated, and whether it has
gone silent. `No engine has ever reported to this database` and `Every engine has stopped reporting` are
shown as errors rather than left to be inferred from a quiet alert list.

Directly, without the console:

```bash
kubectl -n sentinel exec deploy/sentinel-api    -- wget -qO- http://localhost:8080/health/ready
kubectl -n sentinel exec deploy/sentinel-engine -- wget -qO- http://localhost:8080/status
```

`/health/live` says the process is answering and deliberately does not touch the database — a database blip
would otherwise restart every pod, which is the last thing that helps. `/health/ready` says it can reach
the database, so a pod that cannot is taken out of the Service rather than serving errors.

---

## 7. Rehearse before arming

Nothing here is specific to Kubernetes, and skipping it is how a rule blocks the wrong thing.

1. Add the Elasticsearch connection and probe it.
2. Discover fields, so the rule builder offers real field names.
3. Write the rule and **dry-run it against real data**. A rehearsal reads events and executes nothing —
   `DryRunService` takes one dependency, a strategy registry, and has no path to a dispatcher.
4. Read what it *would* have done, then arm it. Arming is a separate permission from saving, for the same
   reason.

To rehearse the response path without touching anything real, run two instances of the sample receiver and
point connections at them:

```bash
STUB_NAME="sms gateway"  dotnet run --project samples/ServiceStub -- --urls http://0.0.0.0:9310
STUB_NAME="security api" dotnet run --project samples/ServiceStub -- --urls http://0.0.0.0:9320
```

`GET /received` shows the exact documents that left the platform. `/fail` answers 500 and `/reject` answers
400, so retry, backoff and dead-lettering can be exercised against something that actually refuses.

---

## 8. Scaling

**The API** runs several replicas as it stands. Sessions survive that because the data-protection key ring
is in the database rather than on each pod; without it, two replicas sign cookies with different keys and
everyone is signed out whenever the load balancer sends them to the other pod.

**The engine** defaults to one, and that is the honest default. It can run as several — every rule is
claimed under a lease before evaluation, so two nodes never evaluate one rule at the same moment and never
double an alert or a block — but a second engine buys availability rather than throughput. Detection
resumes on the next tick either way, and the checkpoint means windows missed while an engine was down are
examined when it returns rather than lost.

Raise it when a tick stops finishing inside its interval. Each node's last tick duration is on the
dashboard; that is the number to watch.

---

## What is deliberately not here

**Backups.** Alerts, the audit trail and every stored credential live in PostgreSQL. Whatever the estate
already does for a database is what should happen to this one; a bespoke mechanism here would be one more
thing to forget. The encryption key is *not* in the database — a restore without it gives you rules and
alerts and no working connections.

**Metrics.** Both hosts log structured events and expose health endpoints, but neither publishes Prometheus
metrics. The signals worth alerting on are in the database and on `/status`: engines that have stopped
reporting, rules with consecutive failures, actions in `DEAD_LETTER`.
