import {
  buildPrompt,
  model,
  normalizeEnvelope,
  prepareRequest,
  validateAgentResult,
} from "./feedback_triage.ts";
import { MAX_TEXT_LENGTH } from "./_lib/feedback_triage_contracts.ts";

function assert(value: unknown, message = "assertion failed"): asserts value {
  if (!value) throw new Error(message);
}

async function rejects(fn: () => unknown | Promise<unknown>, text: string) {
  try {
    await fn();
  } catch (error) {
    assert(String(error).includes(text), String(error));
    return;
  }
  throw new Error(`expected rejection: ${text}`);
}

const envelope = (rawFeedback: string) => ({
  schemaVersion: "1.0",
  envelopeId: "feedback-1",
  sourceId: "synthetic-source",
  receivedAt: "2026-08-23T08:00:00Z",
  trust: "untrusted",
  rawFeedback,
  isolation: {
    boundary: "ingestion-only",
    toolAccess: false,
    agentAccess: "redactor-only",
  },
});

const output = (excerpt = "dark display") => ({
  schemaVersion: "1.0",
  triageId: "triage-1",
  generatedAt: "2026-08-23T11:00:00Z",
  trust: "untrusted-agent-output",
  sourceFeedbackIds: ["feedback-1"],
  duplicateLinks: [],
  themes: [{
    themeId: "theme-1",
    title: "Display",
    summary: "Display preference",
    confidence: 0.9,
    feedbackIds: ["feedback-1"],
    evidence: [{ feedbackId: "feedback-1", excerpt }],
  }],
  recommendations: [{
    recommendationId: "recommendation-1",
    draft: "Consider a display preference",
    confidence: 0.8,
    themeIds: ["theme-1"],
    evidence: [{ feedbackId: "feedback-1", excerpt }],
    audience: "internal",
    disposition: "recommendation-only",
  }],
  authority: {
    sideEffects: "none",
    mayContactUsers: false,
    maySendExternally: false,
    mayInvokeTools: false,
  },
});

Deno.test("synthetic privacy patterns are redacted and raw content is not retained", () => {
  const raw =
    "synthetic@example.invalid +1 (555) 010-0199 account_id=demo-123 api_key=synthetic-secret 123 Example Street";
  const artifact = normalizeEnvelope(
    envelope(raw),
    new Date("2026-08-23T09:00:00Z"),
  );
  assert(!JSON.stringify(artifact).includes("synthetic@example.invalid"));
  assert(!JSON.stringify(artifact).includes("demo-123"));
  assert(artifact.normalizedText.includes("[REDACTED:email]"));
  assert(artifact.handling.rawTextIncluded === false);
  assert(artifact.handling.toolCapableAgentEligible === false);
  assert(artifact.redaction.limitations.includes("not guarantee"));
});

Deno.test("limits and malformed isolation fail closed", async () => {
  await rejects(
    () => normalizeEnvelope(envelope("x".repeat(MAX_TEXT_LENGTH + 1))),
    "Invalid isolated",
  );
  await rejects(
    () =>
      normalizeEnvelope({
        ...envelope("Synthetic feedback"),
        isolation: {
          boundary: "ingestion-only",
          toolAccess: true,
          agentAccess: "redactor-only",
        },
      }),
    "Invalid isolated",
  );
});

Deno.test("prepared prompts are deterministic, bounded, and prohibit contact and authority", async () => {
  const artifact = normalizeEnvelope(
    envelope("Please add a dark display"),
    new Date("2026-08-23T09:00:00Z"),
  );
  const request = await prepareRequest(
    "request-1",
    [artifact],
  );
  assert(request.prompt === buildPrompt([artifact]));
  assert(request.prompt.includes("Do not contact users"));
  assert(request.prompt.includes("Use no tools"));
  assert(request.prompt.length <= 120_000);
  const replay = await prepareRequest("request-1", [artifact]);
  assert(JSON.stringify(replay) === JSON.stringify(request));
});

Deno.test("leakage, contact intent, authority, and ungrounded evidence fail closed", async () => {
  const artifact = normalizeEnvelope(
    envelope("Please add a dark display"),
    new Date("2026-08-23T09:00:00Z"),
  );
  const request = await prepareRequest(
    "request-1",
    [artifact],
    new Date("2026-08-23T10:00:00Z"),
  );
  await rejects(
    () =>
      validateAgentResult("request-1", request, {
        ...output(),
        recommendations: [{
          ...output().recommendations[0],
          draft: "Contact the user",
        }],
      }),
    "forbidden_content",
  );
  await rejects(
    () =>
      validateAgentResult("request-1", request, {
        ...output(),
        authority: { ...output().authority, mayContactUsers: true },
      }),
    "Invalid triage output",
  );
  await rejects(
    () =>
      validateAgentResult("request-1", request, output("invented evidence")),
    "not grounded",
  );
});

Deno.test("rejects output generated after validation time", async () => {
  const artifact = normalizeEnvelope(envelope("Please add a dark display"), new Date("2026-08-23T09:00:00Z"));
  const request = await prepareRequest("request-1", [artifact], new Date("2026-08-23T10:00:00Z"));
  await rejects(
    () => validateAgentResult("request-1", request, output(), new Date("2026-08-23T10:30:00Z")),
    "later than validation time",
  );
});

Deno.test("rejects tampered provenance, prompt, hash, IDs, and malformed output", async () => {
  const artifact = normalizeEnvelope(envelope("Please add a dark display"));
  const request = await prepareRequest("request-1", [artifact]);
  await rejects(
    () => prepareRequest("request-1", [{
      ...artifact,
      provenance: { ...artifact.provenance, inputEnvelopeId: "feedback-2" },
    }]),
    "Invalid normalized artifact",
  );
  await rejects(
    () => validateAgentResult("request-1", { ...request, promptHash: "0".repeat(64) }, output()),
    "hash is invalid",
  );
  await rejects(
    () => validateAgentResult("request-1", { ...request, prompt: `${request.prompt}x` }, output()),
    "does not exactly match",
  );
  await rejects(
    () => validateAgentResult("request-2", request, output()),
    "does not match",
  );
  await rejects(
    () => validateAgentResult("request-1", request, { ...output(), unexpected: true }),
    "Invalid triage output",
  );
});

Deno.test("model writes only a redacted batch before any adapter exists", async () => {
  const writes: Array<{ spec: string; data: Record<string, unknown> }> = [];
  await model.methods.normalize.execute({
    requestId: "request-1",
    envelopes: [envelope("synthetic@example.invalid asks for a dark display")],
  }, {
    logger: { info: () => {} },
    writeResource: (spec, _name, data) => {
      writes.push({ spec, data });
      return Promise.resolve({ name: spec });
    },
  });
  assert(writes.length === 1);
  assert(writes[0].spec === "normalizedBatch");
  assert(!JSON.stringify(writes[0].data).includes("synthetic@example.invalid"));
  assert(
    (writes[0].data.authority as { agentInvoked: boolean }).agentInvoked ===
      false,
  );
});
