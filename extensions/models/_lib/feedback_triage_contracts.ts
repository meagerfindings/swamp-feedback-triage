import { z } from "npm:zod@4";

export const FEEDBACK_TRIAGE_SCHEMA_VERSION = "1.0" as const;
export const MAX_TEXT_LENGTH = 10_000;
export const REDACTION_LIMITATION =
  "pattern-based redaction does not guarantee detection of all private information" as const;

const MAX_COLLECTION_ITEMS = 50;
const Id = z.string().regex(
  /^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/,
  "must be a stable safe ID",
);
const Version = z.string().regex(/^\d{4}\.\d{2}\.\d{2}\.\d+$/);
const Text = z.string().trim().min(1).max(MAX_TEXT_LENGTH);
const Timestamp = z.iso.datetime({ offset: true });
const Confidence = z.number().finite().min(0).max(1);

function unique(message: string) {
  return (values: string[], context: z.RefinementCtx) => {
    const seen = new Map<string, number>();
    values.forEach((value, index) => {
      const first = seen.get(value);
      if (first === undefined) seen.set(value, index);
      else {context.addIssue({
          code: "custom",
          path: [index],
          message: `${message} (first at index ${first})`,
        });}
    });
  };
}

export const feedbackIngestionEnvelopeSchema = z.strictObject({
  schemaVersion: z.literal(FEEDBACK_TRIAGE_SCHEMA_VERSION),
  envelopeId: Id,
  sourceId: Id,
  receivedAt: Timestamp,
  trust: z.literal("untrusted"),
  rawFeedback: z.string().min(1).max(MAX_TEXT_LENGTH),
  isolation: z.strictObject({
    boundary: z.literal("ingestion-only"),
    toolAccess: z.literal(false),
    agentAccess: z.literal("redactor-only"),
  }),
});
export type FeedbackIngestionEnvelope = z.infer<
  typeof feedbackIngestionEnvelopeSchema
>;

const Redaction = z.strictObject({
  method: z.literal("deterministic-redaction"),
  methodVersion: Version,
  performedAt: Timestamp,
  inputEnvelopeId: Id,
  categoriesRemoved: z.array(
    z.enum([
      "email",
      "phone",
      "address",
      "account_identifier",
      "credential",
    ]),
  ).superRefine(unique("duplicate redaction category")),
  replacementCount: z.number().int().nonnegative(),
  limitations: z.literal(REDACTION_LIMITATION),
});

export const normalizedFeedbackArtifactSchema = z.strictObject({
  schemaVersion: z.literal(FEEDBACK_TRIAGE_SCHEMA_VERSION),
  feedbackId: Id,
  sourceId: Id,
  normalizedText: Text,
  labels: z.array(Id).max(MAX_COLLECTION_ITEMS).superRefine(
    unique("duplicate label"),
  ),
  provenance: z.strictObject({
    inputEnvelopeId: Id,
    sourceId: Id,
    normalizedAt: Timestamp,
    normalizer: Id,
    normalizerVersion: Version,
  }),
  redaction: Redaction,
  handling: z.strictObject({
    classification: z.literal("internal-redacted"),
    rawTextIncluded: z.literal(false),
    toolCapableAgentEligible: z.literal(false),
  }),
}).superRefine((artifact, context) => {
  if (artifact.feedbackId !== artifact.provenance.inputEnvelopeId) {
    context.addIssue({
      code: "custom",
      path: ["provenance", "inputEnvelopeId"],
      message: "provenance inputEnvelopeId must match feedbackId",
    });
  }
  if (artifact.sourceId !== artifact.provenance.sourceId) {
    context.addIssue({
      code: "custom",
      path: ["provenance", "sourceId"],
      message: "provenance sourceId must match sourceId",
    });
  }
  if (
    artifact.provenance.inputEnvelopeId !== artifact.redaction.inputEnvelopeId
  ) {
    context.addIssue({
      code: "custom",
      path: ["redaction", "inputEnvelopeId"],
      message:
        "redaction and provenance must reference the same ingestion envelope",
    });
  }
  if (
    Date.parse(artifact.redaction.performedAt) >
      Date.parse(artifact.provenance.normalizedAt)
  ) {
    context.addIssue({
      code: "custom",
      path: ["redaction", "performedAt"],
      message: "redaction must be performed by normalizedAt",
    });
  }
  if (
    artifact.redaction.replacementCount === 0 &&
    artifact.redaction.categoriesRemoved.length !== 0
  ) {
    context.addIssue({
      code: "custom",
      path: ["redaction", "categoriesRemoved"],
      message: "categoriesRemoved must be empty when replacementCount is zero",
    });
  }
  if (
    artifact.redaction.replacementCount > 0 &&
    artifact.redaction.categoriesRemoved.length === 0
  ) {
    context.addIssue({
      code: "custom",
      path: ["redaction", "categoriesRemoved"],
      message: "redaction categories are required when replacements were made",
    });
  }
});
export type NormalizedFeedbackArtifact = z.infer<
  typeof normalizedFeedbackArtifactSchema
>;

const Evidence = z.strictObject({ feedbackId: Id, excerpt: Text });
const DuplicateLink = z.strictObject({
  feedbackId: Id,
  duplicateOfFeedbackId: Id,
  confidence: Confidence,
  evidence: z.array(Evidence).min(1).max(MAX_COLLECTION_ITEMS),
});
const Theme = z.strictObject({
  themeId: Id,
  title: Text,
  summary: Text,
  confidence: Confidence,
  feedbackIds: z.array(Id).min(1).max(MAX_COLLECTION_ITEMS).superRefine(
    unique("duplicate feedbackId"),
  ),
  evidence: z.array(Evidence).min(1).max(MAX_COLLECTION_ITEMS),
});

export const feedbackTriageOutputSchema = z.strictObject({
  schemaVersion: z.literal(FEEDBACK_TRIAGE_SCHEMA_VERSION),
  triageId: Id,
  generatedAt: Timestamp,
  trust: z.literal("untrusted-agent-output"),
  sourceFeedbackIds: z.array(Id).min(1).max(MAX_COLLECTION_ITEMS).superRefine(
    unique("duplicate source feedbackId"),
  ),
  duplicateLinks: z.array(DuplicateLink).max(MAX_COLLECTION_ITEMS),
  themes: z.array(Theme).max(MAX_COLLECTION_ITEMS),
  recommendations: z.array(z.strictObject({
    recommendationId: Id,
    draft: Text,
    confidence: Confidence,
    themeIds: z.array(Id).min(1).max(MAX_COLLECTION_ITEMS).superRefine(
      unique("duplicate themeId"),
    ),
    evidence: z.array(Evidence).min(1).max(MAX_COLLECTION_ITEMS),
    audience: z.literal("internal"),
    disposition: z.literal("recommendation-only"),
  })).max(MAX_COLLECTION_ITEMS),
  authority: z.strictObject({
    sideEffects: z.literal("none"),
    mayContactUsers: z.literal(false),
    maySendExternally: z.literal(false),
    mayInvokeTools: z.literal(false),
  }),
}).superRefine((triage, context) => {
  const sourceIds = new Set(triage.sourceFeedbackIds);
  const themeIds = new Set(triage.themes.map((theme) => theme.themeId));
  const issue = (path: PropertyKey[], message: string) =>
    context.addIssue({ code: "custom", path, message });
  const checkEvidence = (
    items: z.infer<typeof Evidence>[],
    path: PropertyKey[],
  ) =>
    items.forEach((item, index) => {
      if (!sourceIds.has(item.feedbackId)) {
        issue(
          [...path, index, "feedbackId"],
          "evidence must reference sourceFeedbackIds",
        );
      }
    });
  const linkKeys = new Set<string>();
  triage.duplicateLinks.forEach((link, index) => {
    if (
      !sourceIds.has(link.feedbackId) ||
      !sourceIds.has(link.duplicateOfFeedbackId)
    ) {
      issue(
        ["duplicateLinks", index],
        "duplicate links must reference sourceFeedbackIds",
      );
    }
    if (link.feedbackId === link.duplicateOfFeedbackId) {
      issue(["duplicateLinks", index], "feedback cannot duplicate itself");
    }
    const key = [link.feedbackId, link.duplicateOfFeedbackId].sort().join(
      "\u0000",
    );
    if (linkKeys.has(key)) {
      issue(
        ["duplicateLinks", index],
        "duplicate or reciprocal duplicate link",
      );
    } else linkKeys.add(key);
    checkEvidence(link.evidence, ["duplicateLinks", index, "evidence"]);
  });
  triage.themes.forEach((theme, index) => {
    theme.feedbackIds.forEach((id, itemIndex) => {
      if (!sourceIds.has(id)) {
        issue(
          ["themes", index, "feedbackIds", itemIndex],
          "theme must reference sourceFeedbackIds",
        );
      }
    });
    checkEvidence(theme.evidence, ["themes", index, "evidence"]);
    theme.evidence.forEach((evidence, itemIndex) => {
      if (!theme.feedbackIds.includes(evidence.feedbackId)) {
        issue(
          ["themes", index, "evidence", itemIndex, "feedbackId"],
          "theme evidence must reference that theme's feedbackIds",
        );
      }
    });
  });
  triage.recommendations.forEach((recommendation, index) => {
    recommendation.themeIds.forEach((id, itemIndex) => {
      if (!themeIds.has(id)) {
        issue(
          ["recommendations", index, "themeIds", itemIndex],
          "recommendation must reference a theme",
        );
      }
    });
    checkEvidence(recommendation.evidence, [
      "recommendations",
      index,
      "evidence",
    ]);
  });
});
export type FeedbackTriageOutput = z.infer<typeof feedbackTriageOutputSchema>;

export type ValidationDiagnostic = {
  path: string;
  code: string;
  message: string;
};
export type ValidationResult<T> =
  | { success: true; data: T; diagnostics: [] }
  | { success: false; diagnostics: ValidationDiagnostic[] };

const forbiddenKey =
  /^(raw(feedback|text|content)?|email|phone|address|contact(details?|info)?|credential|password|secret|token)$/i;
const forbiddenText = [
  {
    name: "email address",
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
  },
  {
    name: "phone number",
    pattern: /(?:\+\d[\d\s().-]{6,}\d|(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4})/,
  },
  {
    name: "credential",
    pattern:
      /\b(?:api[_ -]?key|password|secret|bearer|access[_ -]?token)\s*[:=]\s*\S+/i,
  },
  {
    name: "contact-user action",
    pattern:
      /\b(?:contact|email|call|message|reply to|reach out to)\s+(?:the\s+)?(?:user|customer|reporter)\b/i,
  },
  {
    name: "external-send action",
    pattern:
      /\b(?:send|post|publish|forward|share)\s+(?:this|it|feedback|message|email)?\s*(?:to|externally|publicly|outside)\b/i,
  },
] as const;

function leakageDiagnostics(input: unknown): ValidationDiagnostic[] {
  const diagnostics: ValidationDiagnostic[] = [];
  const visit = (value: unknown, path: string[]) => {
    if (typeof value === "string") {
      forbiddenText.forEach(({ name, pattern }) => {
        if (pattern.test(value)) {
          diagnostics.push({
            path: path.join("."),
            code: "forbidden_content",
            message: `${name} is forbidden after redaction`,
          });
        }
      });
    } else if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, [...path, String(index)]));
    } else if (value && typeof value === "object") {
      Object.entries(value).forEach(([key, item]) => {
        if (forbiddenKey.test(key)) {
          diagnostics.push({
            path: [...path, key].join("."),
            code: "forbidden_field",
            message:
              "raw or private feedback field is forbidden after ingestion",
          });
        }
        visit(item, [...path, key]);
      });
    }
  };
  visit(input, []);
  return diagnostics;
}

function validate<T>(
  schema: z.ZodType<T>,
  input: unknown,
  scan: boolean,
): ValidationResult<T> {
  const parsed = schema.safeParse(input);
  const schemaDiagnostics = parsed.success
    ? []
    : parsed.error.issues.map((issue) => ({
      path: issue.path.map(String).join("."),
      code: issue.code,
      message: issue.message,
    }));
  const diagnostics = [
    ...schemaDiagnostics,
    ...(scan && parsed.success ? leakageDiagnostics(parsed.data) : []),
  ].sort((a, b) =>
    a.path.localeCompare(b.path) || a.code.localeCompare(b.code) ||
    a.message.localeCompare(b.message)
  );
  return parsed.success && diagnostics.length === 0
    ? { success: true, data: parsed.data, diagnostics: [] }
    : { success: false, diagnostics };
}

export const validateFeedbackIngestionEnvelope = (input: unknown) =>
  validate(feedbackIngestionEnvelopeSchema, input, false);
export const validateNormalizedFeedbackArtifact = (input: unknown) =>
  validate(normalizedFeedbackArtifactSchema, input, true);
export const validateFeedbackTriageOutput = (input: unknown) =>
  validate(feedbackTriageOutputSchema, input, true);
