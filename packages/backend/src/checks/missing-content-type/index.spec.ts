import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import missingContentTypeCheck from "./index";

describe("Missing Content-Type Check", () => {
  it("should detect missing content-type header when response has body", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {}, // No content-type header
      body: "Response body content",
    });

    const executionHistory = await runCheck(missingContentTypeCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "missing-content-type",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "checkMissingContentType",
            findings: [
              {
                name: "Content-Type Header Missing",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run when response has no body", async () => {
    const request = createMockRequest({
      id: "2",
      host: "example.com",
      method: "GET",
      path: "/test",
    });

    const response = createMockResponse({
      id: "2",
      code: 204, // No content
      headers: {},
      body: undefined, // No body
    });

    const executionHistory = await runCheck(missingContentTypeCheck, [
      { request, response },
    ]);

    // When check doesn't run, execution history is empty
    expect(executionHistory).toMatchObject([]);
  });

  it("should find no issues when content-type header is present", async () => {
    const request = createMockRequest({
      id: "3",
      host: "example.com",
      method: "GET",
      path: "/test",
    });

    const response = createMockResponse({
      id: "3",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Response body content",
    });

    const executionHistory = await runCheck(missingContentTypeCheck, [
      { request, response },
    ]);

    // When check runs but finds no issues, execution history is non-empty with empty findings
    expect(executionHistory).toMatchObject([
      {
        checkId: "missing-content-type",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "checkMissingContentType",
            findings: [], // Empty findings array
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should find no issues when content-type header is present with multiple values", async () => {
    const request = createMockRequest({
      id: "4",
      host: "example.com",
      method: "GET",
      path: "/test",
    });

    const response = createMockResponse({
      id: "4",
      code: 200,
      headers: { "content-type": ["text/html", "application/json"] },
      body: "Response body content",
    });

    const executionHistory = await runCheck(missingContentTypeCheck, [
      { request, response },
    ]);

    // When check runs but finds no issues, execution history is non-empty with empty findings
    expect(executionHistory).toMatchObject([
      {
        checkId: "missing-content-type",
        targetRequestId: "4",
        status: "completed",
        steps: [
          {
            stepName: "checkMissingContentType",
            findings: [], // Empty findings array
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run when response is undefined", async () => {
    const request = createMockRequest({
      id: "5",
      host: "example.com",
      method: "GET",
      path: "/test",
    });

    const executionHistory = await runCheck(missingContentTypeCheck, [
      { request, response: undefined },
    ]);

    // When check doesn't run, execution history is empty
    expect(executionHistory).toMatchObject([]);
  });
});
