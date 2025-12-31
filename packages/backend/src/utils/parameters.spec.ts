import { createMockRequest, createMockResponse } from "engine";
import { describe, expect, it } from "vitest";

import {
  createRequestWithParameter,
  extractParameters,
  extractReflectedParameters,
  hasParameters,
  type Parameter,
} from "./parameters";

const createContext = (
  request: ReturnType<typeof createMockRequest>,
  response?: ReturnType<typeof createMockResponse>,
) => ({
  target: { request, response },
  sdk: {} as never,
  runtime: {} as never,
  config: {} as never,
});

describe("extractParameters", () => {
  describe("query parameters", () => {
    it("should extract query parameters with values", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "foo=bar&baz=qux",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([
        { name: "foo", value: "bar", source: "query" },
        { name: "baz", value: "qux", source: "query" },
      ]);
    });

    it("should extract parameters with empty values", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "ble=&test=2",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([
        { name: "ble", value: "", source: "query" },
        { name: "test", value: "2", source: "query" },
      ]);
    });

    it("should extract parameter with only empty value", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "empty=",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([
        { name: "empty", value: "", source: "query" },
      ]);
    });

    it("should return empty array when no query string", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([]);
    });

    it("should handle URL encoded values", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "param=hello%20world&special=%3Cscript%3E",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([
        { name: "param", value: "hello world", source: "query" },
        { name: "special", value: "<script>", source: "query" },
      ]);
    });

    it("should extract parameters without values", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "debug&verbose&trace",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([
        { name: "debug", value: "", source: "query" },
        { name: "verbose", value: "", source: "query" },
        { name: "trace", value: "", source: "query" },
      ]);
    });

    it("should extract mixed query parameters", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "debug&foo=bar&verbose",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([
        { name: "debug", value: "", source: "query" },
        { name: "foo", value: "bar", source: "query" },
        { name: "verbose", value: "", source: "query" },
      ]);
    });
  });

  describe("body parameters (form)", () => {
    it("should extract form body parameters", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/submit",
        headers: { "Content-Type": ["application/x-www-form-urlencoded"] },
        body: "username=admin&password=secret",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([
        { name: "username", value: "admin", source: "body" },
        { name: "password", value: "secret", source: "body" },
      ]);
    });

    it("should extract form parameters with empty values", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/submit",
        headers: { "Content-Type": ["application/x-www-form-urlencoded"] },
        body: "empty=&filled=value",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([
        { name: "empty", value: "", source: "body" },
        { name: "filled", value: "value", source: "body" },
      ]);
    });

    it("should not extract body parameters for GET requests", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        headers: { "Content-Type": ["application/x-www-form-urlencoded"] },
        body: "foo=bar",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([]);
    });
  });

  describe("body parameters (JSON)", () => {
    it("should extract JSON body parameters", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/api",
        headers: { "Content-Type": ["application/json"] },
        body: JSON.stringify({ user: "admin", role: "viewer" }),
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([
        { name: "user", value: "admin", source: "body" },
        { name: "role", value: "viewer", source: "body" },
      ]);
    });

    it("should extract JSON parameters with empty string values", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/api",
        headers: { "Content-Type": ["application/json"] },
        body: JSON.stringify({ empty: "", filled: "value" }),
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([
        { name: "empty", value: "", source: "body" },
        { name: "filled", value: "value", source: "body" },
      ]);
    });

    it("should stringify non-string JSON values", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/api",
        headers: { "Content-Type": ["application/json"] },
        body: JSON.stringify({ count: 42, active: true, items: [1, 2, 3] }),
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([
        { name: "count", value: "42", source: "body" },
        { name: "active", value: "true", source: "body" },
        { name: "items", value: "[1,2,3]", source: "body" },
      ]);
    });

    it("should handle invalid JSON gracefully", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/api",
        headers: { "Content-Type": ["application/json"] },
        body: "not valid json",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([]);
    });
  });

  describe("combined parameters", () => {
    it("should extract both query and body parameters", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/submit",
        query: "action=update",
        headers: { "Content-Type": ["application/x-www-form-urlencoded"] },
        body: "data=value",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([
        { name: "action", value: "update", source: "query" },
        { name: "data", value: "value", source: "body" },
      ]);
    });
  });
});

describe("extractReflectedParameters", () => {
  it("should return parameters that are reflected in response", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/search",
      query: "q=test&page=1",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "Search results for: test",
    });

    const context = createContext(request, response);
    const parameters = extractReflectedParameters(context);

    expect(parameters).toEqual([{ name: "q", value: "test", source: "query" }]);
  });

  it("should return empty array when no parameters are reflected", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/search",
      query: "q=secretvalue",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "No results found",
    });

    const context = createContext(request, response);
    const parameters = extractReflectedParameters(context);

    expect(parameters).toEqual([]);
  });

  it("should return all parameters when response is undefined", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/search",
      query: "q=test&page=1",
    });

    const context = createContext(request, undefined);
    const parameters = extractReflectedParameters(context);

    expect(parameters).toEqual([
      { name: "q", value: "test", source: "query" },
      { name: "page", value: "1", source: "query" },
    ]);
  });
});

describe("createRequestWithParameter", () => {
  it("should modify query parameter value", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "foo=bar&baz=qux",
    });

    const context = createContext(request);
    const parameter: Parameter = { name: "foo", value: "bar", source: "query" };
    const spec = createRequestWithParameter(context, parameter, "newvalue");

    expect(spec.getQuery()).toBe("foo=newvalue&baz=qux");
  });

  it("should modify form body parameter value", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/submit",
      headers: { "Content-Type": ["application/x-www-form-urlencoded"] },
      body: "username=admin&password=secret",
    });

    const context = createContext(request);
    const parameter: Parameter = {
      name: "username",
      value: "admin",
      source: "body",
    };
    const spec = createRequestWithParameter(context, parameter, "attacker");

    expect(spec.getBody()?.toText()).toBe("username=attacker&password=secret");
  });

  it("should modify JSON body parameter value", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/api",
      headers: { "Content-Type": ["application/json"] },
      body: JSON.stringify({ user: "admin", role: "viewer" }),
    });

    const context = createContext(request);
    const parameter: Parameter = {
      name: "user",
      value: "admin",
      source: "body",
    };
    const spec = createRequestWithParameter(context, parameter, "attacker");

    expect(spec.getBody()?.toText()).toBe(
      JSON.stringify({ user: "attacker", role: "viewer" }),
    );
  });

  it("should modify header value", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      headers: { "X-Custom": ["original"] },
    });

    const context = createContext(request);
    const parameter: Parameter = {
      name: "X-Custom",
      value: "original",
      source: "header",
    };
    const spec = createRequestWithParameter(context, parameter, "modified");

    expect(spec.getHeader("X-Custom")).toEqual(["modified"]);
  });
});

describe("hasParameters", () => {
  it("should return true when request has query parameters", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "foo=bar",
    });

    expect(hasParameters({ request, response: undefined })).toBe(true);
  });

  it("should return true when request has body", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/submit",
      body: "data=value",
    });

    expect(hasParameters({ request, response: undefined })).toBe(true);
  });

  it("should return false when request has no parameters or body", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "",
    });

    expect(hasParameters({ request, response: undefined })).toBe(false);
  });
});
