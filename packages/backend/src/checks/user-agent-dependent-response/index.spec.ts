import {
  createMockRequest,
  createMockResponse,
  runCheck,
  type SendHandler,
} from "engine";
import { describe, expect, it } from "vitest";

import userAgentCheck from "./index";

describe("user-agent-dependent-response check", () => {
  it("should not flag when responses are identical", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "test response",
    });

    const sendHandler: SendHandler = (spec) => {
      const mockRequest = createMockRequest({
        id: "2",
        host: spec.getHost(),
        method: spec.getMethod(),
        path: spec.getPath(),
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {},
        body: "test response",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(userAgentCheck, [
      { request, response },
    ], { sendHandler });

    expect(executionHistory).toEqual([
      {
        checkId: "user-agent-dependent-response",
        targetRequestId: "1",
        steps: [
          {
            stepName: "probeUserAgents",
            stateBefore: {
              originalStatus: 0,
              originalLength: 0,
              probes: [],
            },
            stateAfter: {
              originalStatus: 200,
              originalLength: 13,
              probes: [
                {
                  userAgent: "desktop",
                  responseCode: 200,
                  bodyLength: 13,
                },
                {
                  userAgent: "mobile",
                  responseCode: 200,
                  bodyLength: 13,
                },
              ],
            },
            findings: [],
            result: "continue",
            nextStep: "evaluateDifferences",
          },
          {
            stepName: "evaluateDifferences",
            stateBefore: {
              originalStatus: 200,
              originalLength: 13,
              probes: [
                {
                  userAgent: "desktop",
                  responseCode: 200,
                  bodyLength: 13,
                },
                {
                  userAgent: "mobile",
                  responseCode: 200,
                  bodyLength: 13,
                },
              ],
            },
            stateAfter: {
              originalStatus: 200,
              originalLength: 13,
              probes: [
                {
                  userAgent: "desktop",
                  responseCode: 200,
                  bodyLength: 13,
                },
                {
                  userAgent: "mobile",
                  responseCode: 200,
                  bodyLength: 13,
                },
              ],
            },
            findings: [],
            result: "done",
          },
        ],
        status: "completed",
      },
    ]);
  });

  it("should flag when status code differs", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "test response",
    });

    const sendHandler: SendHandler = (spec) => {
      const userAgentHeader = spec.getHeader("User-Agent");
      const userAgent = userAgentHeader?.[0] ?? "";
      const isMobile = userAgent.toLowerCase().includes("mobile");

      const mockRequest = createMockRequest({
        id: "2",
        host: spec.getHost(),
        method: spec.getMethod(),
        path: spec.getPath(),
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: isMobile ? 302 : 200,
        headers: {},
        body: "test response",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(userAgentCheck, [
      { request, response },
    ], { sendHandler });

    expect(executionHistory).toMatchObject([
      {
        checkId: "user-agent-dependent-response",
        targetRequestId: "1",
        steps: [
          {
            stepName: "probeUserAgents",
            stateBefore: {
              originalStatus: 0,
              originalLength: 0,
              probes: [],
            },
            stateAfter: {
              originalStatus: 200,
              originalLength: 13,
              probes: [
                {
                  userAgent: "desktop",
                  responseCode: 200,
                  bodyLength: 13,
                },
                {
                  userAgent: "mobile",
                  responseCode: 302,
                  bodyLength: 13,
                },
              ],
            },
            findings: [],
            result: "continue",
            nextStep: "evaluateDifferences",
          },
          {
            stepName: "evaluateDifferences",
            findings: [
              {
                name: "User agent dependent response detected",
                severity: "info",
                correlation: {
                  requestID: "1",
                },
              },
            ],
            result: "done",
          },
        ],
        status: "completed",
      },
    ]);
  });

  it("should flag when body length difference exceeds tolerance", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "test response",
    });

    const sendHandler: SendHandler = (spec) => {
      const userAgentHeader = spec.getHeader("User-Agent");
      const userAgent = userAgentHeader?.[0] ?? "";
      const isMobile = userAgent.toLowerCase().includes("mobile");

      const mockRequest = createMockRequest({
        id: "2",
        host: spec.getHost(),
        method: spec.getMethod(),
        path: spec.getPath(),
      });

      const body = isMobile
        ? `test response${"x".repeat(101)}`
        : "test response";

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {},
        body,
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(userAgentCheck, [
      { request, response },
    ], { sendHandler });

    expect(executionHistory).toMatchObject([
      {
        checkId: "user-agent-dependent-response",
        targetRequestId: "1",
        steps: [
          {
            stepName: "probeUserAgents",
            result: "continue",
            nextStep: "evaluateDifferences",
          },
          {
            stepName: "evaluateDifferences",
            findings: [
              {
                name: "User agent dependent response detected",
                severity: "info",
                correlation: {
                  requestID: "1",
                },
              },
            ],
            result: "done",
          },
        ],
        status: "completed",
      },
    ]);
  });

  it("should not flag when body length difference is within tolerance", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "test response",
    });

    const sendHandler: SendHandler = (spec) => {
      const userAgentHeader = spec.getHeader("User-Agent");
      const userAgent = userAgentHeader?.[0] ?? "";
      const isMobile = userAgent.toLowerCase().includes("mobile");

      const mockRequest = createMockRequest({
        id: "2",
        host: spec.getHost(),
        method: spec.getMethod(),
        path: spec.getPath(),
      });

      const body = isMobile
        ? `test response${"x".repeat(100)}`
        : "test response";

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {},
        body,
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(userAgentCheck, [
      { request, response },
    ], { sendHandler });

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });

  it("should handle when some probe responses omit the body", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "test response",
    });

    const sendHandler: SendHandler = (spec) => {
      const userAgentHeader = spec.getHeader("User-Agent");
      const userAgent = userAgentHeader?.[0] ?? "";
      const isMobile = userAgent.toLowerCase().includes("mobile");

      const mockRequest = createMockRequest({
        id: "2",
        host: spec.getHost(),
        method: spec.getMethod(),
        path: spec.getPath(),
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {},
        body: isMobile ? undefined : "test response",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(userAgentCheck, [
      { request, response },
    ], { sendHandler });

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });
});
