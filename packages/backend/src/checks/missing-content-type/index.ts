import { defineCheck, done, Severity } from "engine";

import { findingBuilder } from "../../utils/findings";
import { keyStrategy } from "../../utils/key";

export default defineCheck<Record<never, never>>(({ step }) => {
  step("checkMissingContentType", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    // Only check responses that have a body
    const body = response.getBody();
    if (body === undefined) {
      return done({ state });
    }

    // Check if Content-Type header is missing
    const contentType = response.getHeader("content-type");
    if (contentType === undefined || contentType.length === 0) {
      const finding = findingBuilder({
        name: "Content-Type Header Missing",
        severity: Severity.INFO,
        request: context.target.request,
      })
        .withDescription(
          "This response is missing the Content-Type header, forcing the browser to guess how to handle the content based on its structure and content.",
        )
        .withImpact(
          "Without explicit content type instructions, browsers may misinterpret malicious content as executable code. Attackers can exploit this by uploading files that appear to be images or documents but contain HTML or JavaScript. When victims view these files, their browsers execute the embedded code, leading to cross-site scripting attacks or other security compromises.",
        )
        .withRecommendation(
          "Explicitly declare content types for all responses using the Content-Type header.",
        )
        .build();

      return done({ state, findings: [finding] });
    }

    return done({ state });
  });

  return {
    metadata: {
      id: "missing-content-type",
      name: "Missing Content-Type Header",
      description:
        "Detects responses that do not specify a Content-Type header, which can lead to browser MIME type sniffing vulnerabilities",
      type: "passive",
      tags: ["security-headers", "xss", "mime-type"],
      severities: [Severity.INFO],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (context) =>
      context.response !== undefined &&
      context.response.getBody() !== undefined,
  };
});
