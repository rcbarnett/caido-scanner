import { describe, expect, it } from "vitest";

import { CSPParser } from ".";

describe("CSPParser", () => {
  describe("parse", () => {
    it("should parse a simple CSP header", () => {
      const cspHeader = "default-src 'self'; script-src 'self' 'unsafe-inline'";
      const result = CSPParser.parse(cspHeader);

      expect(result).toMatchObject({
        kind: "Success",
        raw: cspHeader,
        directives: [
          {
            name: "default-src",
            values: ["'self'"],
          },
          {
            name: "script-src",
            values: ["'self'", "'unsafe-inline'"],
          },
        ],
      });
    });

    it("should parse CSP with multiple values per directive", () => {
      const cspHeader = "script-src 'self' https://example.com 'unsafe-inline'";
      const result = CSPParser.parse(cspHeader);

      expect(result).toMatchObject({
        kind: "Success",
        raw: cspHeader,
        directives: [
          {
            name: "script-src",
            values: ["'self'", "https://example.com", "'unsafe-inline'"],
          },
        ],
      });
    });

    it("should handle empty CSP header", () => {
      const result = CSPParser.parse("");
      expect(result).toMatchObject({
        kind: "Success",
        raw: "",
        directives: [],
      });
    });

    it("should handle CSP header with only whitespace", () => {
      const result = CSPParser.parse("   ");
      expect(result).toMatchObject({
        kind: "Success",
        raw: "   ",
        directives: [],
      });
    });

    it("should handle CSP header with extra semicolons", () => {
      const cspHeader = "default-src 'self';; script-src 'self';;";
      const result = CSPParser.parse(cspHeader);

      expect(result).toMatchObject({
        kind: "Failed",
      });
    });

    it("should handle CSP header with spaces around semicolons", () => {
      const cspHeader =
        "default-src 'self' ; script-src 'self' ; style-src 'self'";
      const result = CSPParser.parse(cspHeader);

      expect(result).toMatchObject({
        kind: "Success",
        raw: cspHeader,
        directives: [
          { name: "default-src" },
          { name: "script-src" },
          { name: "style-src" },
        ],
      });
    });

    it("should handle directive with no values", () => {
      const cspHeader = "default-src 'self'; object-src";
      const result = CSPParser.parse(cspHeader);

      expect(result).toMatchObject({
        kind: "Success",
        raw: cspHeader,
        directives: [
          {
            name: "default-src",
            values: ["'self'"],
          },
          {
            name: "object-src",
            values: [],
          },
        ],
      });
    });

    it("should handle CSP header with invalid directive", () => {
      const cspHeader = "default-src 'self'; invalid-directive";
      const result = CSPParser.parse(cspHeader);

      expect(result).toMatchObject({
        kind: "Failed",
      });
    });

    it("should parse complex GitHub CSP header", () => {
      const cspHeader =
        "default-src 'none'; base-uri 'self'; child-src github.githubassets.com github.com/assets-cdn/worker/ github.com/assets/ gist.github.com/assets-cdn/worker/; connect-src 'self' uploads.github.com www.githubstatus.com collector.github.com raw.githubusercontent.com api.github.com github-cloud.s3.amazonaws.com github-production-repository-file-5c1aeb.s3.amazonaws.com github-production-upload-manifest-file-7fdce7.s3.amazonaws.com github-production-user-asset-6210df.s3.amazonaws.com *.rel.tunnels.api.visualstudio.com wss://*.rel.tunnels.api.visualstudio.com github.githubassets.com objects-origin.githubusercontent.com copilot-proxy.githubusercontent.com proxy.individual.githubcopilot.com proxy.business.githubcopilot.com proxy.enterprise.githubcopilot.com *.actions.githubusercontent.com wss://*.actions.githubusercontent.com productionresultssa0.blob.core.windows.net/ productionresultssa1.blob.core.windows.net/ productionresultssa2.blob.core.windows.net/ productionresultssa3.blob.core.windows.net/ productionresultssa4.blob.core.windows.net/ productionresultssa5.blob.core.windows.net/ productionresultssa6.blob.core.windows.net/ productionresultssa7.blob.core.windows.net/ productionresultssa8.blob.core.windows.net/ productionresultssa9.blob.core.windows.net/ productionresultssa10.blob.core.windows.net/ productionresultssa11.blob.core.windows.net/ productionresultssa12.blob.core.windows.net/ productionresultssa13.blob.core.windows.net/ productionresultssa14.blob.core.windows.net/ productionresultssa15.blob.core.windows.net/ productionresultssa16.blob.core.windows.net/ productionresultssa17.blob.core.windows.net/ productionresultssa18.blob.core.windows.net/ productionresultssa19.blob.core.windows.net/ github-production-repository-image-32fea6.s3.amazonaws.com github-production-release-asset-2e65be.s3.amazonaws.com insights.github.com wss://alive.github.com wss://alive-staging.github.com api.githubcopilot.com api.individual.githubcopilot.com api.business.githubcopilot.com api.enterprise.githubcopilot.com; font-src github.githubassets.com; form-action 'self' github.com gist.github.com copilot-workspace.githubnext.com objects-origin.githubusercontent.com; frame-ancestors 'none'; frame-src viewscreen.githubusercontent.com notebooks.githubusercontent.com; img-src 'self' data: blob: github.githubassets.com media.githubusercontent.com camo.githubusercontent.com identicons.github.com avatars.githubusercontent.com private-avatars.githubusercontent.com github-cloud.s3.amazonaws.com objects.githubusercontent.com release-assets.githubusercontent.com secured-user-images.githubusercontent.com/ user-images.githubusercontent.com/ private-user-images.githubusercontent.com opengraph.githubassets.com marketplace-screenshots.githubusercontent.com/ copilotprodattachments.blob.core.windows.net/github-production-copilot-attachments/ github-production-user-asset-6210df.s3.amazonaws.com customer-stories-feed.github.com spotlights-feed.github.com objects-origin.githubusercontent.com *.githubusercontent.com; manifest-src 'self'; media-src github.com user-images.githubusercontent.com/ secured-user-images.githubusercontent.com/ private-user-images.githubusercontent.com github-production-user-asset-6210df.s3.amazonaws.com gist.github.com; script-src github.githubassets.com; style-src 'unsafe-inline' github.githubassets.com; upgrade-insecure-requests; worker-src github.githubassets.com github.com/assets-cdn/worker/ github.com/assets/ gist.github.com/assets-cdn/worker/";
      const result = CSPParser.parse(cspHeader);

      expect(result).toMatchObject({
        kind: "Success",
        raw: cspHeader,
        directives: [
          {
            name: "default-src",
            values: ["'none'"],
          },
          {
            name: "base-uri",
            values: ["'self'"],
          },
          {
            name: "child-src",
            values: [
              "github.githubassets.com",
              "github.com/assets-cdn/worker/",
              "github.com/assets/",
              "gist.github.com/assets-cdn/worker/",
            ],
          },
          {
            name: "connect-src",
            values: [
              "'self'",
              "uploads.github.com",
              "www.githubstatus.com",
              "collector.github.com",
              "raw.githubusercontent.com",
              "api.github.com",
              "github-cloud.s3.amazonaws.com",
              "github-production-repository-file-5c1aeb.s3.amazonaws.com",
              "github-production-upload-manifest-file-7fdce7.s3.amazonaws.com",
              "github-production-user-asset-6210df.s3.amazonaws.com",
              "*.rel.tunnels.api.visualstudio.com",
              "wss://*.rel.tunnels.api.visualstudio.com",
              "github.githubassets.com",
              "objects-origin.githubusercontent.com",
              "copilot-proxy.githubusercontent.com",
              "proxy.individual.githubcopilot.com",
              "proxy.business.githubcopilot.com",
              "proxy.enterprise.githubcopilot.com",
              "*.actions.githubusercontent.com",
              "wss://*.actions.githubusercontent.com",
              "productionresultssa0.blob.core.windows.net/",
              "productionresultssa1.blob.core.windows.net/",
              "productionresultssa2.blob.core.windows.net/",
              "productionresultssa3.blob.core.windows.net/",
              "productionresultssa4.blob.core.windows.net/",
              "productionresultssa5.blob.core.windows.net/",
              "productionresultssa6.blob.core.windows.net/",
              "productionresultssa7.blob.core.windows.net/",
              "productionresultssa8.blob.core.windows.net/",
              "productionresultssa9.blob.core.windows.net/",
              "productionresultssa10.blob.core.windows.net/",
              "productionresultssa11.blob.core.windows.net/",
              "productionresultssa12.blob.core.windows.net/",
              "productionresultssa13.blob.core.windows.net/",
              "productionresultssa14.blob.core.windows.net/",
              "productionresultssa15.blob.core.windows.net/",
              "productionresultssa16.blob.core.windows.net/",
              "productionresultssa17.blob.core.windows.net/",
              "productionresultssa18.blob.core.windows.net/",
              "productionresultssa19.blob.core.windows.net/",
              "github-production-repository-image-32fea6.s3.amazonaws.com",
              "github-production-release-asset-2e65be.s3.amazonaws.com",
              "insights.github.com",
              "wss://alive.github.com",
              "wss://alive-staging.github.com",
              "api.githubcopilot.com",
              "api.individual.githubcopilot.com",
              "api.business.githubcopilot.com",
              "api.enterprise.githubcopilot.com",
            ],
          },
          {
            name: "font-src",
            values: ["github.githubassets.com"],
          },
          {
            name: "form-action",
            values: [
              "'self'",
              "github.com",
              "gist.github.com",
              "copilot-workspace.githubnext.com",
              "objects-origin.githubusercontent.com",
            ],
          },
          {
            name: "frame-ancestors",
            values: ["'none'"],
          },
          {
            name: "frame-src",
            values: [
              "viewscreen.githubusercontent.com",
              "notebooks.githubusercontent.com",
            ],
          },
          {
            name: "img-src",
            values: [
              "'self'",
              "data:",
              "blob:",
              "github.githubassets.com",
              "media.githubusercontent.com",
              "camo.githubusercontent.com",
              "identicons.github.com",
              "avatars.githubusercontent.com",
              "private-avatars.githubusercontent.com",
              "github-cloud.s3.amazonaws.com",
              "objects.githubusercontent.com",
              "release-assets.githubusercontent.com",
              "secured-user-images.githubusercontent.com/",
              "user-images.githubusercontent.com/",
              "private-user-images.githubusercontent.com",
              "opengraph.githubassets.com",
              "marketplace-screenshots.githubusercontent.com/",
              "copilotprodattachments.blob.core.windows.net/github-production-copilot-attachments/",
              "github-production-user-asset-6210df.s3.amazonaws.com",
              "customer-stories-feed.github.com",
              "spotlights-feed.github.com",
              "objects-origin.githubusercontent.com",
              "*.githubusercontent.com",
            ],
          },
          {
            name: "manifest-src",
            values: ["'self'"],
          },
          {
            name: "media-src",
            values: [
              "github.com",
              "user-images.githubusercontent.com/",
              "secured-user-images.githubusercontent.com/",
              "private-user-images.githubusercontent.com",
              "github-production-user-asset-6210df.s3.amazonaws.com",
              "gist.github.com",
            ],
          },
          {
            name: "script-src",
            values: ["github.githubassets.com"],
          },
          {
            name: "style-src",
            values: ["'unsafe-inline'", "github.githubassets.com"],
          },
          {
            name: "upgrade-insecure-requests",
            values: [],
          },
          {
            name: "worker-src",
            values: [
              "github.githubassets.com",
              "github.com/assets-cdn/worker/",
              "github.com/assets/",
              "gist.github.com/assets-cdn/worker/",
            ],
          },
        ],
      });
    });
  });
});
