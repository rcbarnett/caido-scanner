import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import cspNotEnforcedCheck from "./index";

describe("CSP Not Enforced Check", () => {
  it("should find no issues when CSP header is completely missing", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspNotEnforcedCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-not-enforced",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "checkCspNotEnforced",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run on non-HTML responses", async () => {
    const request = createMockRequest({
      id: "2",
      host: "example.com",
      method: "GET",
      path: "/api/data",
    });

    const response = createMockResponse({
      id: "2",
      code: 200,
      headers: { "content-type": ["application/json"] },
      body: '{"data": "test"}',
    });

    const executionHistory = await runCheck(cspNotEnforcedCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([]);
  });

  it("should find no issues when CSP header is present", async () => {
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
        "content-security-policy": ["default-src 'self'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspNotEnforcedCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-not-enforced",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "checkCspNotEnforced",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run when response is undefined", async () => {
    const request = createMockRequest({
      id: "4",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const executionHistory = await runCheck(cspNotEnforcedCheck, [
      { request, response: undefined },
    ]);

    expect(executionHistory).toMatchObject([]);
  });

  it("should detect Report-Only header instead of CSP header", async () => {
    const request = createMockRequest({
      id: "5",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "5",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy-report-only": [
          "default-src 'self'; script-src 'self'",
        ],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspNotEnforcedCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-not-enforced",
        targetRequestId: "5",
        status: "completed",
        steps: [
          {
            stepName: "checkCspNotEnforced",
            findings: [
              {
                name: "Content security policy: not enforced",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not report empty Report-Only header", async () => {
    const request = createMockRequest({
      id: "6",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "6",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy-report-only": [""],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspNotEnforcedCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-not-enforced",
        targetRequestId: "6",
        status: "completed",
        steps: [
          {
            stepName: "checkCspNotEnforced",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect malformed CSP syntax", async () => {
    const request = createMockRequest({
      id: "7",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "7",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": ["invalid-directive-name 'self'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspNotEnforcedCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-not-enforced",
        targetRequestId: "7",
        status: "completed",
        steps: [
          {
            stepName: "checkCspNotEnforced",
            findings: [
              {
                name: "Content security policy: malformed syntax",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect empty CSP directives", async () => {
    const request = createMockRequest({
      id: "8",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "8",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": [""],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspNotEnforcedCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-not-enforced",
        targetRequestId: "8",
        status: "completed",
        steps: [
          {
            stepName: "checkCspNotEnforced",
            findings: [
              {
                name: "Content security policy: no directives",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });
});
