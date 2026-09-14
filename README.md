# blindai-sdk

Fail-closed Python client for the BlindAI authorization API.

```bash
pip install blindai-sdk    # not yet published; install from git for now
```

```python
from blindai import BlindAIClient

client = BlindAIClient(
    api_key=os.environ["BLINDAI_API_KEY"],
    base_url=os.environ["BLINDAI_BASE_URL"],   # required: no production default
)

decision = client.authorize(
    "Look up invoice 4471 for the Contoso account",
    user_id="u-1024",
    tool="crm_lookup",
    preset="strict",
)

if decision.blocked:
    raise RuntimeError(decision.reason or "blocked by policy")
```

## The one rule

**Errors raise. No error path in this client produces an allow.**

- A response with neither `blocked` nor `allowed` raises `ContractError`.
- A `blocked` or `allowed` that is not a bool raises rather than being coerced.
- A 404, a timeout, a connection failure and a non-JSON body all raise.
- There is no `continue_on_error` option and no collapsed batch verdict.

If your application needs a fallback when authorization is unavailable, catch the error and make
that decision in your own code, where a reviewer can see it.

## API

### `BlindAIClient(api_key, base_url, ...)`

| Option | Required | Default | Notes |
|---|---|---|---|
| `api_key` | yes | — | Must start with `ba_` |
| `base_url` | yes | — | No default: state your deployment explicitly |
| `timeout` | no | `10.0` | Seconds per request |
| `max_retries` | no | `2` | Retries 5xx, 408 and 429 only |
| `auth_style` | no | `"bearer"` | Or `"x-api-key"`; both are accepted |
| `rate_limiter` | no | `None` | Raises when empty; never returns a verdict |
| `transport` | no | — | An `httpx` transport, for tests |

- `authorize(input_text, **fields) -> Decision` · `POST /v1/authorize`
- `scan(input_text, **fields) -> Decision` · `POST /v1/scan`, identical models
- `rag_scan(documents, threshold=None) -> dict` · `POST /v1/rag/scan`
- `authorize_batch(requests) -> list[dict]` — each item is `{"ok": True, "decision": ...}` or
  `{"ok": False, "error": ...}`. A failed item carries **no** decision, so it cannot be misread as
  an allow.

`input_text` is the only required field. Everything else is defaulted server-side: `user_id` →
`"anonymous"`, `action` → `"query"`, `role` → `"user"` (lowercase), `preset` → `"balanced"`. Also
accepted: `agent_id`, `tool`, `session_id`, `parameters`, `target_space_id`.

**There is no `metadata` field.** The server does not accept one, and passing an unknown field
raises rather than being silently dropped.

### `Decision`

`blocked` is the enforcement signal. `is_threat` is for reporting — a request can carry detected
threats and still be allowed, so gating on `is_threat` refuses work the policy permitted.

### Errors

| Class | When |
|---|---|
| `ContractError` | The response carried no usable decision |
| `AuthError` | 401 / 403; the server's `detail` is included |
| `ValidationError` | 422; built from `loc` and `msg`, `body` prefix stripped |
| `PresetUnavailableError` | 503; a preset needs server-side configuration |
| `ApiError` | Any other non-2xx; `retryable` says whether it was retried |
| `TimeoutError` / `TransportError` | The request never completed |
| `RateLimitExceeded` | The local limiter refused before a request was made |

## Testing your integration

```python
from blindai.testing import decision, stub_transport

client = BlindAIClient("ba_live_t", "http://test",
                       transport=stub_transport([decision.block("prompt injection")]))
```

`stub_transport` **fails an unscripted call** rather than inventing a response — the same rule the
client follows, applied to tests. Builders: `allow()`, `block()`, `flagged()`, `malformed()`,
`status()`, `down()`.

## Server behaviour worth knowing

- **`POWER_USER` is not a role.** The server knows `admin | user | viewer | guest | foreign`;
  anything else is enforced as `guest`, which is fail-closed. This client passes roles through
  unchanged and maps nothing — inventing a promotion would grant more access than the caller asked
  for.
- **Presets can 503.** Presets using the intent classifier refuse to start without an API key
  rather than dropping a detection layer, so a deployment without one answers 503 for the default
  preset instead of quietly downgrading. That surfaces as `PresetUnavailableError` and is not
  retried: it is a configuration answer.
- **422 bodies echo your request.** FastAPI's validation entries carry an `input` field containing
  the body you submitted, including `input_text`. This client reads `loc` and `msg` only and never
  stores or logs `input`.

## Development

```bash
pip install -e ".[dev]"
pytest tests --ignore=tests/contract     # 34 unit + 9 behavioural
python scripts/no_local_verdicts.py blindai --parser parse.py
BLINDAI_BASE_URL=… BLINDAI_API_KEY=… pytest tests/contract
```

Contract tests **fail** when the two variables are absent, so a green build cannot mean "we never
checked". Set `BLINDAI_CONTRACT_OPTIONAL=1` to skip them locally; CI must not.

Two invariants gate every release, as `needs:` dependencies of the publish job rather than as
branch-protection checks — so they hold whether or not the repository has protected branches:

1. **Static** — the client may produce an allow-shaped value in exactly one place, the response
   parser. Catches a fabricated allow, including dataclass field defaults and parameter defaults.
2. **Behavioural** — every public call either makes exactly one request or raises, and the decision
   returned was built from the body served for *that* request, proven by a per-response nonce.

The second exists because the first structurally cannot see a call that never asked, or an answer
that was reused. Both are mutation-tested: a cache-shaped client and a rollout-shaped client each
fail four assertions.
