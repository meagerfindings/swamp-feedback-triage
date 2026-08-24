import {
  buildPrompt,
  globalArgumentsSchema,
  invocationClaimAuditSchema,
  legacyNormalizedFeedbackArtifactSchema,
  model,
  normalizeArgumentsSchema,
  normalizedBatchSchema,
  normalizeEnvelope,
  prepareArgumentsSchema,
  preparedRequestSchema,
  prepareRequest,
  validateAgentResult,
  validateArgumentsSchema,
  validatedTriageSchema,
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
      validateAgentResult(
        "request-1",
        request,
        output(),
        new Date("2026-08-23T10:30:00Z"),
      ),
    "later than validation time",
  );
});

Deno.test("rejects tampered provenance, prompt, hash, IDs, and malformed output", async () => {
  const artifact = normalizeEnvelope(envelope("Please add a dark display"));
  const request = await prepareRequest("request-1", [artifact]);
  await rejects(
    () =>
      prepareRequest("request-1", [{
        ...artifact,
        provenance: { ...artifact.provenance, inputEnvelopeId: "feedback-2" },
      }]),
    "Invalid normalized artifact",
  );
  await rejects(
    () =>
      validateAgentResult("request-1", {
        ...request,
        promptHash: "0".repeat(64),
      }, output()),
    "hash is invalid",
  );
  await rejects(
    () =>
      validateAgentResult("request-1", {
        ...request,
        prompt: `${request.prompt}x`,
      }, output()),
    "does not exactly match",
  );
  await rejects(
    () => validateAgentResult("request-2", request, output()),
    "does not match",
  );
  await rejects(
    () =>
      validateAgentResult("request-1", request, {
        ...output(),
        unexpected: true,
      }),
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

Deno.test("pre-extraction model globals and exact retained artifact shape remain compatible", async () => {
  const globals = globalArgumentsSchema.parse({
    agentCwd: "/tmp/moment-savor-feedback-triage-agent",
    maxPromptBytes: 120000,
  });
  assert(globals.agentCwd === "/tmp/moment-savor-feedback-triage-agent");
  const legacyArtifact = legacyNormalizedFeedbackArtifactSchema.parse({
    schemaVersion: "1.0",
    feedbackId: "feedback-1",
    sourceId: "synthetic-source",
    normalizedText: "Please add a dark display",
    labels: [],
    provenance: {
      inputEnvelopeId: "feedback-1",
      sourceId: "synthetic-source",
      normalizedAt: "2026-08-17T09:00:00Z",
      normalizer: "moment-savor-feedback-triage",
      normalizerVersion: "2026.08.17.1",
    },
    redaction: {
      method: "deterministic-redaction",
      methodVersion: "2026.08.17.1",
      performedAt: "2026-08-17T09:00:00Z",
      inputEnvelopeId: "feedback-1",
      categoriesRemoved: [],
      replacementCount: 0,
      reviewStatus: "not_reviewed",
      limitations:
        "pattern-based redaction does not guarantee detection of all private information",
    },
    handling: {
      classification: "internal-redacted",
      rawTextIncluded: false,
      toolCapableAgentEligible: true,
    },
  });
  const request = await prepareRequest(
    "request-1",
    [legacyArtifact],
    globals,
    new Date("2026-08-17T10:00:00Z"),
  );
  assert("agentCwd" in request);
  assert(
    request.agentCwd ===
      "/tmp/moment-savor-feedback-triage-agent/request-request-1",
  );
  preparedRequestSchema.parse(request);
});

Deno.test("legacy compatibility remains fail-closed for forged provenance and leaked content", async () => {
  const artifact = legacyNormalizedFeedbackArtifactSchema.parse({
    schemaVersion: "1.0",
    feedbackId: "feedback-1",
    sourceId: "synthetic-source",
    normalizedText: "Please add a dark display",
    labels: [],
    provenance: {
      inputEnvelopeId: "feedback-1",
      sourceId: "synthetic-source",
      normalizedAt: "2026-08-17T09:00:00Z",
      normalizer: "moment-savor-feedback-triage",
      normalizerVersion: "2026.08.17.1",
    },
    redaction: {
      method: "deterministic-redaction",
      methodVersion: "2026.08.17.1",
      performedAt: "2026-08-17T09:00:00Z",
      inputEnvelopeId: "feedback-1",
      categoriesRemoved: [],
      replacementCount: 0,
      reviewStatus: "not_reviewed",
      limitations:
        "pattern-based redaction does not guarantee detection of all private information",
    },
    handling: {
      classification: "internal-redacted",
      rawTextIncluded: false,
      toolCapableAgentEligible: true,
    },
  });
  await rejects(
    () =>
      prepareRequest("request-1", [{
        ...artifact,
        normalizedText: "leak@example.invalid",
      }]),
    "Invalid normalized artifact",
  );
  await rejects(
    () =>
      prepareRequest("request-1", [{
        ...artifact,
        provenance: { ...artifact.provenance, inputEnvelopeId: "feedback-2" },
      }]),
    "Invalid normalized artifact",
  );
});

Deno.test("active audited validate inputs are strict, bound, and preserved", async () => {
  const artifact = normalizeEnvelope(
    envelope("Please add a dark display"),
    new Date("2026-08-23T09:00:00Z"),
  );
  const request = await prepareRequest(
    "request-1",
    [artifact],
    {
      agentCwd: "/tmp/feedback-triage-test",
      maxPromptBytes: 120000,
    },
    new Date("2026-08-23T10:00:00Z"),
  );
  assert("agentCwd" in request);
  const invocation = {
    invocationId: "request-1",
    provider: "amp",
    model: "synthetic-model",
    promptHash: request.promptHash,
    cwd: request.agentCwd,
    success: true,
  };
  const invocationClaim = invocationClaimAuditSchema.parse({
    operation: "invokeAndParse",
    invocationId: "request-1",
    provider: "amp",
    model: "synthetic-model",
    cwd: request.agentCwd,
    promptHash: request.promptHash,
    toolProfile: "readonly",
    sandbox: {
      mode: "auto",
      provider: "amp",
      credentialAccess: "provider",
      network: "allow",
      profilePath: "",
      required: true,
    },
  });
  const args = validateArgumentsSchema.parse({
    requestId: "request-1",
    request,
    agentOutput: output(),
    invocation,
    invocationClaim,
  });
  const result = await validateAgentResult(
    args.requestId,
    args.request,
    args.agentOutput,
    { invocation, invocationClaim },
    new Date("2026-08-23T12:00:00Z"),
  );
  const persisted = validatedTriageSchema.parse(result);
  assert("invocation" in persisted && "invocationClaim" in persisted);
  assert(persisted.invocation.promptHash === request.promptHash);
  await rejects(
    () =>
      validateAgentResult(
        "request-1",
        request,
        output(),
        {
          invocation: { ...invocation, cwd: "/tmp/wrong" },
          invocationClaim,
        },
      ),
    "does not match",
  );
});

Deno.test("model methods accept the active workflow shapes and persist upgrade-compatible resources", async () => {
  const legacyArtifact = legacyNormalizedFeedbackArtifactSchema.parse({
    schemaVersion: "1.0",
    feedbackId: "feedback-1",
    sourceId: "synthetic-source",
    normalizedText: "Please add a dark display",
    labels: [],
    provenance: {
      inputEnvelopeId: "feedback-1",
      sourceId: "synthetic-source",
      normalizedAt: "2026-08-17T09:00:00Z",
      normalizer: "moment-savor-feedback-triage",
      normalizerVersion: "2026.08.17.1",
    },
    redaction: {
      method: "deterministic-redaction",
      methodVersion: "2026.08.17.1",
      performedAt: "2026-08-17T09:00:00Z",
      inputEnvelopeId: "feedback-1",
      categoriesRemoved: [],
      replacementCount: 0,
      reviewStatus: "not_reviewed",
      limitations:
        "pattern-based redaction does not guarantee detection of all private information",
    },
    handling: {
      classification: "internal-redacted",
      rawTextIncluded: false,
      toolCapableAgentEligible: true,
    },
  });
  normalizedBatchSchema.parse({
    schemaVersion: "1.0",
    requestId: "request-1",
    artifacts: [legacyArtifact],
    normalizedAt: "2026-08-17T09:00:00Z",
    authority: { agentInvoked: false, toolsInvoked: false },
  });
  normalizeArgumentsSchema.parse({
    requestId: "request-1",
    envelopes: [envelope("Please add a dark display")],
  });
  const prepareArgs = prepareArgumentsSchema.parse({
    requestId: "request-1",
    artifacts: [legacyArtifact],
  });
  const writes: Array<{ spec: string; data: Record<string, unknown> }> = [];
  const context = {
    globalArgs: {
      agentCwd: "/tmp/moment-savor-feedback-triage-agent",
      maxPromptBytes: 120000,
    },
    logger: { info: () => {} },
    writeResource: (
      spec: string,
      _name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ spec, data });
      return Promise.resolve({ name: spec });
    },
  };
  await model.methods.prepare.execute(prepareArgs, context);
  assert(writes.length === 1 && writes[0].spec === "request");
  const request = preparedRequestSchema.parse(writes[0].data);
  assert("agentCwd" in request);
  assert(
    request.agentCwd ===
      "/tmp/moment-savor-feedback-triage-agent/request-request-1",
  );
  const invocation = {
    invocationId: "request-1",
    provider: "amp",
    model: "synthetic-model",
    promptHash: request.promptHash,
    cwd: request.agentCwd,
    success: true,
  };
  const invocationClaim = {
    operation: "invokeAndParse" as const,
    invocationId: "request-1",
    provider: "amp" as const,
    model: "synthetic-model",
    cwd: request.agentCwd,
    promptHash: request.promptHash,
    toolProfile: "readonly" as const,
    sandbox: {
      mode: "auto" as const,
      provider: "amp" as const,
      credentialAccess: "provider" as const,
      network: "allow" as const,
      profilePath: "",
      required: true as const,
    },
  };
  const validateArgs = validateArgumentsSchema.parse({
    requestId: "request-1",
    request,
    agentOutput: output(),
    invocation,
    invocationClaim,
  });
  await model.methods.validate.execute(validateArgs, context);
  const validatedWrite = writes.at(1);
  assert(validatedWrite?.spec === "validatedTriage");
  const triage = validatedTriageSchema.parse(validatedWrite.data);
  assert("invocation" in triage && "invocationClaim" in triage);
});
