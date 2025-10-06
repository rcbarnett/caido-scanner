import { defineCheck, done, Severity } from "engine";

import { CSPParser } from "../../parsers/csp";
import { findingBuilder, keyStrategy } from "../../utils";

export default defineCheck(({ step }) => {
  step("checkCspClickjacking", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    // Only check HTML responses
    const contentType = response.getHeader("content-type")?.[0] ?? "";
    if (contentType === undefined || !contentType.includes("text/html")) {
      return done({ state });
    }

    const cspHeader = response.getHeader("content-security-policy");

    // Check if CSP header is missing
    if (!cspHeader || cspHeader.length === 0) {
      return done({ state });
    }

    const cspValue = cspHeader[0] ?? "";
    const parsedCsp = CSPParser.parse(cspValue);

    // Check if parsing was successful
    if (parsedCsp.kind === "Failed") {
      return done({ state });
    }

    // Find frame-ancestors directive
    const frameAncestorsDirective = parsedCsp.directives.find(
      (d) => d.name === "frame-ancestors",
    );

    // Check if frame-ancestors directive is missing
    if (!frameAncestorsDirective) {
      const finding = findingBuilder({
        name: "Content security policy: allows clickjacking",
        severity: Severity.MEDIUM,
        request: context.target.request,
      })
        .withDescription(
          "The Content Security Policy is missing the frame-ancestors directive, which can lead to clickjacking attacks.",
        )
        .withImpact(
          "The application can be embedded in malicious frames, allowing clickjacking attacks that trick users into performing unintended actions.",
        )
        .withRecommendation(
          "Add a frame-ancestors directive to restrict where the application can be embedded. Use 'none' to prevent all framing, or 'self' to allow only same-origin framing.",
        )
        .withArtifacts("CSP Header", [cspValue])
        .build();

      return done({ state, findings: [finding] });
    }

    // Check for overly permissive frame-ancestors values
    const frameAncestorsValues = frameAncestorsDirective.values;

    // Check for wildcard
    if (frameAncestorsValues.includes("*")) {
      const finding = findingBuilder({
        name: "Content security policy: allows clickjacking",
        severity: Severity.HIGH,
        request: context.target.request,
      })
        .withDescription(
          "The Content Security Policy allows the application to be embedded in frames from any source with wildcard (*), which can lead to clickjacking attacks.",
        )
        .withImpact(
          "The application can be embedded in malicious frames from any domain, allowing complete bypass of frame embedding restrictions.",
        )
        .withRecommendation(
          "Replace wildcard (*) with specific trusted domains or use 'self' for same-origin framing only.",
        )
        .withArtifacts("Unsafe Values", ["*"])
        .build();

      return done({ state, findings: [finding] });
    }

    // Check for data: and blob: sources
    const unsafeSources = frameAncestorsValues.filter(
      (value) => value.startsWith("data:") || value.startsWith("blob:"),
    );

    if (unsafeSources.length > 0) {
      const finding = findingBuilder({
        name: "Content security policy: allows clickjacking",
        severity: Severity.MEDIUM,
        request: context.target.request,
      })
        .withDescription(
          "The Content Security Policy allows the application to be embedded in frames from data: and blob: sources, which can lead to clickjacking attacks.",
        )
        .withImpact(
          "The application can be embedded in data URL frames, allowing clickjacking attacks through data URLs and bypass of frame embedding restrictions.",
        )
        .withRecommendation(
          "Remove data: and blob: sources from frame-ancestors unless absolutely necessary for legitimate use cases.",
        )
        .withArtifacts("Unsafe Sources", unsafeSources)
        .build();

      return done({ state, findings: [finding] });
    }

    // Check for HTTP sources without HTTPS
    const httpSources = frameAncestorsValues.filter(
      (value) => value.startsWith("http:") && !value.startsWith("https:"),
    );

    if (httpSources.length > 0) {
      const finding = findingBuilder({
        name: "Content security policy: allows clickjacking",
        severity: Severity.LOW,
        request: context.target.request,
      })
        .withDescription(
          "The Content Security Policy allows the application to be embedded in frames from HTTP sources, which can be intercepted and modified.",
        )
        .withImpact(
          "HTTP frame sources can be intercepted by attackers, allowing man-in-the-middle attacks that modify frame content.",
        )
        .withRecommendation(
          "Use HTTPS sources only or ensure HTTP sources are from trusted, internal networks.",
        )
        .withArtifacts("HTTP Sources", httpSources)
        .build();

      return done({ state, findings: [finding] });
    }

    return done({ state });
  });

  return {
    metadata: {
      id: "csp-clickjacking",
      name: "Content security policy: allows clickjacking",
      description:
        "Checks for missing or overly permissive frame-ancestors directives in Content Security Policy headers, which can lead to clickjacking attacks",
      type: "passive",
      tags: [
        "csp",
        "security-headers",
        "clickjacking",
        "frame-ancestors",
        "ui-redressing",
      ],
      severities: [Severity.LOW, Severity.MEDIUM, Severity.HIGH],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (context) => {
      if (context.response === undefined) return false;
      const contentType = context.response.getHeader("content-type")?.[0] ?? "";
      return contentType.includes("text/html");
    },
  };
});
