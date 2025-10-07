import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import cspClickjackingCheck from "./index";

describe("CSP Clickjacking Check", () => {
  it("should detect missing frame-ancestors directive", async () => {
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
        "content-security-policy": ["default-src 'self'; script-src 'self'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [
              {
                name: "Content security policy: allows clickjacking",
                severity: "info",
                description: expect.stringContaining(
                  "The Content Security Policy is missing the frame-ancestors directive",
                ),
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

  it("should detect unsafe values in frame-ancestors directive", async () => {
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
        "content-security-policy": ["frame-ancestors *"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "2",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [
              {
                name: "Content security policy: allows clickjacking",
                severity: "info",
                description: expect.stringContaining(
                  "allows the application to be embedded in frames from sources other than 'self' or 'none'",
                ),
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

  it("should detect multiple unsafe values in frame-ancestors directive", async () => {
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
        "content-security-policy": [
          "frame-ancestors 'self' https://trusted.com",
        ],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [
              {
                name: "Content security policy: allows clickjacking",
                severity: "info",
                description: expect.stringContaining(
                  "allows the application to be embedded in frames from sources other than 'self' or 'none'",
                ),
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

  it("should detect 'none' as safe value in frame-ancestors directive", async () => {
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
        "content-security-policy": ["frame-ancestors 'none'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "4",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect 'self' as safe value in frame-ancestors directive", async () => {
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
        "content-security-policy": ["frame-ancestors 'self'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "5",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should find no issues when CSP header is missing", async () => {
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

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "6",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect missing frame-ancestors directive when CSP header is empty", async () => {
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
        "content-security-policy": [""],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "7",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [
              {
                name: "Content security policy: allows clickjacking",
                severity: "info",
                description: expect.stringContaining(
                  "The Content Security Policy is missing the frame-ancestors directive",
                ),
                correlation: {
                  requestID: "7",
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

  it("should find no issues with secure frame-ancestors 'self' 'none'", async () => {
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
        "content-security-policy": ["frame-ancestors 'self' 'none'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "8",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should find no issues when CSP parsing fails", async () => {
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
        "content-security-policy": ["invalid-csp-syntax!!!"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "9",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run on non-HTML responses", async () => {
    const request = createMockRequest({
      id: "10",
      host: "example.com",
      method: "GET",
      path: "/api/data",
    });

    const response = createMockResponse({
      id: "10",
      code: 200,
      headers: {
        "content-type": ["application/json"],
        "content-security-policy": ["frame-ancestors *"],
      },
      body: '{"data": "test"}',
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([]);
  });

  it("should not run when response is undefined", async () => {
    const request = createMockRequest({
      id: "11",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response: undefined },
    ]);

    expect(executionHistory).toMatchObject([]);
  });

  it("should include artifacts in finding description for missing frame-ancestors", async () => {
    const request = createMockRequest({
      id: "12",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "12",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": ["default-src 'self'; script-src 'self'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    const finding = executionHistory[0]?.steps[0]?.findings[0];
    expect(finding).toBeDefined();
    expect(finding?.description).toContain("### CSP Header");
    expect(finding?.description).toContain(
      "- default-src 'self'; script-src 'self'",
    );
    expect(finding?.description).toContain("## Impact");
    expect(finding?.description).toContain("## Recommendation");
  });

  it("should include artifacts in finding description for unsafe values", async () => {
    const request = createMockRequest({
      id: "13",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "13",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": [
          "frame-ancestors 'self' https://trusted.com",
        ],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    const finding = executionHistory[0]?.steps[0]?.findings[0];
    expect(finding).toBeDefined();
    expect(finding?.description).toContain("### Unsafe Values");
    expect(finding?.description).toContain("- https://trusted.com");
    expect(finding?.description).toContain("## Impact");
    expect(finding?.description).toContain("## Recommendation");
  });
});
