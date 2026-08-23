# Feedback Triage

`@mgreten/feedback-triage` is a deterministic, local Swamp model that prepares
redacted feedback for an adapter and validates returned triage output. It does
not invoke agents or tools, contact people, send externally, publish anything,
or grant authority to act.

## Privacy boundary

- `normalize` accepts one isolated ingestion envelope per feedback item and
  writes only redacted artifacts. Raw feedback is never persisted.
- All text is capped at 10,000 characters; oversize input is rejected rather
  than truncated or partially processed.
- Pattern redaction detects common emails, telephone numbers, credentials,
  account identifiers, and street addresses. **Pattern redaction is not a PII
  guarantee**: it cannot reliably identify every person, secret, identifier,
  or private fact. Review redacted artifacts before any broader use.
- `prepare` builds a bounded deterministic prompt for a separately owned
  adapter. The prompt reiterates no-tool, no-contact, and no-authority rules.
- `validate` treats returned output as untrusted and rejects leaked private
  patterns, ungrounded evidence, ID mismatches, invalid chronology, and any
  authority other than recommendation-only with zero side effects.

## Contract

All resources use schema version `1.0`:

- `normalizedBatch`: redacted artifacts only; its authority records that no
  agent or tools ran.
- `request`: deterministic prompt, SHA-256 hash, and artifact IDs. It contains
  no adapter credentials, working directory, or provider-specific audit data.
- `validatedTriage`: a validated, untrusted, recommendation-only output.

Resource IDs are stable logical names (`normalized-`, `request-`, and `triage-`
plus `requestId`) in Swamp's versioned store. Given identical validated inputs,
resource payloads are deterministic: normalization uses the envelope receipt
time, preparation uses the latest normalization time, and validation records the
agent output time. Reusing a request ID may create another identical stored
version; callers that require write-once semantics must reuse the previously
returned data handle or choose a unique ID.

The model is intentionally adapter-free. A caller that sends `request.prompt`
to an agent is responsible for its provider, sandbox, transport, and audit
trail. Feed its response into `validate`; do not treat a valid result as an
authorization to contact users, call tools, or make external changes.

## Use

```sh
swamp model create @mgreten/feedback-triage feedback-triage
swamp model method run feedback-triage normalize --input requestId=example-1 \
  --input envelopes='[{"schemaVersion":"1.0","envelopeId":"feedback-1","sourceId":"survey","receivedAt":"2026-08-23T12:00:00Z","trust":"untrusted","rawFeedback":"Synthetic feedback","isolation":{"boundary":"ingestion-only","toolAccess":false,"agentAccess":"redactor-only"}}]'
```

Then pass `normalizedBatch.artifacts` to `prepare`. Validate only an adapter
response whose evidence is grounded in those exact artifacts.

Validated output remains explicitly side-effect free:

```json
{
  "authority": {
    "sideEffects": "none",
    "mayContactUsers": false,
    "maySendExternally": false,
    "mayInvokeTools": false
  }
}
```

Licensed under the MIT License. See [LICENSE](LICENSE).
