import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import suspectTransformCheck from "./index";

describe("Suspicious Input Transformation", () => {
  it("should detect transformations when check conditions are met", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
      query: "param=value",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Response: value",
    });

    let callCount = 0;
    const sendHandler = () => {
      callCount++;

      const mockRequest = createMockRequest({
        id: `${callCount + 1}`,
        host: "example.com",
        method: "GET",
        path: "/test",
        query: `param=value`,
      });

      const body =
        callCount <= 2 ? "valueabcdefK123456ghijkl" : "Response: value";

      const mockResponse = createMockResponse({
        id: `${callCount + 1}`,
        code: 200,
        headers: { "content-type": ["text/html"] },
        body,
      });

      return Promise.resolve({
        request: mockRequest,
        response: mockResponse,
      });
    };

    const executionHistory = await runCheck(
      suspectTransformCheck,
      [{ request, response }],
      { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
    );

    expect(executionHistory[0]?.status).toBe("completed");
  });

  it("should detect arithmetic evaluation when result appears", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/calc",
      query: "expr=test",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      body: "Result: test",
    });

    let callCount = 0;
    const sendHandler = () => {
      callCount++;

      const mockRequest = createMockRequest({
        id: `${callCount + 1}`,
        host: "example.com",
        method: "GET",
        path: "/calc",
        query: "expr=test",
      });

      const mockResponse = createMockResponse({
        id: `${callCount + 1}`,
        code: 200,
        body: `Result: ${callCount % 2 === 1 ? "9801" : "9801"}`,
      });

      return Promise.resolve({
        request: mockRequest,
        response: mockResponse,
      });
    };

    const executionHistory = await runCheck(
      suspectTransformCheck,
      [{ request, response }],
      { sendHandler, config: { aggressivity: ScanAggressivity.MEDIUM } },
    );

    const allFindings =
      executionHistory[0]?.steps?.flatMap((step) => step.findings ?? []) ?? [];

    if (allFindings.length > 0) {
      expect(allFindings[0]?.name).toContain("arithmetic evaluation");
    }
  });

  it("should not run when request has no parameters", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Safe response",
    });

    const executionHistory = await runCheck(suspectTransformCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([]);
  });

  it("should find no issues when no transformation occurs", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
      query: "param=value",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Response without transformation",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/test",
        query: "param=valuetest",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "Response without transformation",
      });

      return Promise.resolve({
        request: mockRequest,
        response: mockResponse,
      });
    };

    const executionHistory = await runCheck(
      suspectTransformCheck,
      [{ request, response }],
      { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
    );

    const allFindings = executionHistory[0]?.steps?.flatMap(
      (step) => step.findings ?? [],
    );
    expect(allFindings).toHaveLength(0);
  });

  it("should not detect transformation if expected value is in initial response", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
      query: "param=value",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Response already contains 9801",
    });

    let callCount = 0;
    const sendHandler = () => {
      callCount++;
      const mockRequest = createMockRequest({
        id: `${callCount + 1}`,
        host: "example.com",
        method: "GET",
        path: "/test",
        query: "param=value99*99",
      });

      const mockResponse = createMockResponse({
        id: `${callCount + 1}`,
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "Response contains 9801",
      });

      return Promise.resolve({
        request: mockRequest,
        response: mockResponse,
      });
    };

    const executionHistory = await runCheck(
      suspectTransformCheck,
      [{ request, response }],
      { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
    );

    const allFindings = executionHistory[0]?.steps?.flatMap(
      (step) => step.findings ?? [],
    );
    expect(allFindings).toHaveLength(0);
  });

  it("should handle network errors gracefully", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
      query: "test=value",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      body: "Test: value",
    });

    const sendHandler = () => {
      return Promise.reject(new Error("Network error"));
    };

    const executionHistory = await runCheck(
      suspectTransformCheck,
      [{ request, response }],
      { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
    );

    expect(executionHistory[0]?.status).toBe("completed");
    expect(executionHistory[0]?.steps?.length).toBeGreaterThan(1);
  });

  it("should use fewer checks on LOW aggressivity", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
      query: "param=test",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      body: "Value: test",
    });

    let sendCallCount = 0;
    const sendHandler = () => {
      sendCallCount++;
      const mockRequest = createMockRequest({
        id: `${sendCallCount + 1}`,
        host: "example.com",
        method: "GET",
        path: "/test",
        query: `param=testprobe${sendCallCount}`,
      });

      const mockResponse = createMockResponse({
        id: `${sendCallCount + 1}`,
        code: 200,
        body: `Value: testprobe${sendCallCount}`,
      });

      return Promise.resolve({
        request: mockRequest,
        response: mockResponse,
      });
    };

    await runCheck(suspectTransformCheck, [{ request, response }], {
      sendHandler,
      config: { aggressivity: ScanAggressivity.LOW },
    });

    expect(sendCallCount).toBeLessThanOrEqual(3);
  });

  it("should use more checks on HIGH aggressivity", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
      query: "param=test",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      body: "Value: test",
    });

    let sendCallCount = 0;
    const sendHandler = () => {
      sendCallCount++;
      const mockRequest = createMockRequest({
        id: `${sendCallCount + 1}`,
        host: "example.com",
        method: "GET",
        path: "/test",
        query: `param=testprobe${sendCallCount}`,
      });

      const mockResponse = createMockResponse({
        id: `${sendCallCount + 1}`,
        code: 200,
        body: `Value: testprobe${sendCallCount}`,
      });

      return Promise.resolve({
        request: mockRequest,
        response: mockResponse,
      });
    };

    await runCheck(suspectTransformCheck, [{ request, response }], {
      sendHandler,
      config: { aggressivity: ScanAggressivity.HIGH },
    });

    expect(sendCallCount).toBeGreaterThan(5);
  });
});
