import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import cspMalformedSyntaxCheck from "./index";

describe("CSP Malformed Syntax Check", () => {
  it("should detect invalid directive names", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": [
          "invalid-directive 'self'; script-src 'self'",
        ],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspMalformedSyntaxCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-malformed-syntax",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "checkCspMalformedSyntax",
            findings: [
              {
                name: "Content security policy: malformed syntax",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect malformed syntax with extra semicolons", async () => {
    const request = createMockRequest({
      id: "2",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "2",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": ["default-src 'self';; script-src 'self'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspMalformedSyntaxCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-malformed-syntax",
        targetRequestId: "2",
        status: "completed",
        steps: [
          {
            stepName: "checkCspMalformedSyntax",
            findings: [
              {
                name: "Content security policy: malformed syntax",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should find no issues with valid CSP", async () => {
    const request = createMockRequest({
      id: "3",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "3",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": ["default-src 'self'; script-src 'self'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspMalformedSyntaxCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-malformed-syntax",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "checkCspMalformedSyntax",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should find no issues with duplicate directives (valid CSP syntax)", async () => {
    const request = createMockRequest({
      id: "4",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "4",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": [
          "script-src 'self'; script-src 'unsafe-inline'",
        ],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspMalformedSyntaxCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-malformed-syntax",
        targetRequestId: "4",
        status: "completed",
        steps: [
          {
            stepName: "checkCspMalformedSyntax",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run on non-HTML responses", async () => {
    const request = createMockRequest({
      id: "5",
      host: "example.com",
      method: "GET",
      path: "/api/data",
    });

    const response = createMockResponse({
      id: "5",
      code: 200,
      headers: { "content-type": ["application/json"] },
      body: '{"data": "test"}',
    });

    const executionHistory = await runCheck(cspMalformedSyntaxCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([]);
  });

  it("should not run when CSP header is missing", async () => {
    const request = createMockRequest({
      id: "6",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "6",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspMalformedSyntaxCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-malformed-syntax",
        targetRequestId: "6",
        status: "completed",
        steps: [
          {
            stepName: "checkCspMalformedSyntax",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });
});
