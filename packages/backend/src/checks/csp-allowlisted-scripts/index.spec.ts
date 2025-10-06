import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import cspAllowlistedScriptsCheck from "./index";

describe("CSP Allowlisted Scripts Check", () => {
  it("should detect HTTPS external script sources", async () => {
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
          "script-src 'self' https://cdn.example.com",
        ],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: [
              {
                name: "Content security policy: allowlisted script resources",
                severity: "info",
                description: expect.stringContaining("Allowlisted Resources"),
                correlation: {
                  requestID: "1",
                  locations: [],
                },
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect HTTP external script sources", async () => {
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
        "content-security-policy": [
          "script-src 'self' http://insecure-cdn.com",
        ],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "2",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: [
              {
                name: "Content security policy: allowlisted script resources",
                severity: "info",
                description: expect.stringContaining("Allowlisted Resources"),
                correlation: {
                  requestID: "2",
                  locations: [],
                },
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect protocol-relative external script sources", async () => {
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
        "content-security-policy": ["script-src 'self' //cdn.example.com"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: [
              {
                name: "Content security policy: allowlisted script resources",
                severity: "info",
                description: expect.stringContaining("Allowlisted Resources"),
                correlation: {
                  requestID: "3",
                  locations: [],
                },
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect multiple external script sources", async () => {
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
          "script-src 'self' https://cdn1.com https://cdn2.com http://cdn3.com //cdn4.com",
        ],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "4",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: [
              {
                name: "Content security policy: allowlisted script resources",
                severity: "info",
                description: expect.stringContaining("Allowlisted Resources"),
                correlation: {
                  requestID: "4",
                  locations: [],
                },
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should use default-src when script-src is not present", async () => {
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
        "content-security-policy": ["default-src 'self' https://external.com"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "5",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: [
              {
                name: "Content security policy: allowlisted script resources",
                severity: "info",
                description: expect.stringContaining("Allowlisted Resources"),
                correlation: {
                  requestID: "5",
                  locations: [],
                },
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should find no issues when no external sources are present", async () => {
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
        "content-security-policy": [
          "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
        ],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "6",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should find no issues when only nonces and hashes are used", async () => {
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
        "content-security-policy": [
          "script-src 'self' 'nonce-abc123' 'sha256-hash'",
        ],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "7",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run when CSP header is missing", async () => {
    const request = createMockRequest({
      id: "8",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "8",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "8",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run when CSP header is empty", async () => {
    const request = createMockRequest({
      id: "9",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "9",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": [""],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "9",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run when no script-src or default-src directive exists", async () => {
    const request = createMockRequest({
      id: "11",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "11",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": ["img-src 'self' https://images.com"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "11",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run on non-HTML responses", async () => {
    const request = createMockRequest({
      id: "12",
      host: "example.com",
      method: "GET",
      path: "/api/data",
    });

    const response = createMockResponse({
      id: "12",
      code: 200,
      headers: {
        "content-type": ["application/json"],
        "content-security-policy": ["script-src 'self' https://external.com"],
      },
      body: '{"data": "test"}',
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([]);
  });

  it("should not run when response is undefined", async () => {
    const request = createMockRequest({
      id: "13",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response: undefined },
    ]);

    expect(executionHistory).toMatchObject([]);
  });

  it("should include artifacts in finding description", async () => {
    const request = createMockRequest({
      id: "14",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "14",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": [
          "script-src 'self' https://cdn1.com https://cdn2.com",
        ],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    const finding = executionHistory[0]?.steps[0]?.findings[0];
    expect(finding).toBeDefined();
    expect(finding?.description).toContain("Allowlisted Resources");
    expect(finding?.description).toContain("- https://cdn1.com");
    expect(finding?.description).toContain("- https://cdn2.com");
    expect(finding?.description).toContain("## Impact");
    expect(finding?.description).toContain("## Recommendation");
  });
});
