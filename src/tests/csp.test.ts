import { describe, it, expect } from "vitest";
import {
  BASE_CSP_DIRECTIVES,
  STRICT_CSP_DIRECTIVES,
  DOMAIN_ALLOWLIST_DOCUMENTATION,
  generateNonce,
  buildCspHeader,
  STATIC_CSP_HEADER,
  validateCspHeader,
} from "../config/csp";

import vercelConfigRaw from "../../vercel.json?raw";
import nginxContent from "../../nginx.conf?raw";
import viteContent from "../../vite.config.ts?raw";
import indexHtmlContent from "../../index.html?raw";

describe("Content Security Policy (CSP) & Subresource Integrity (SRI) Suite - Issue #211", () => {
  describe("1. Required Directives Presence & Exact Header Parity", () => {
    it("verifies base CSP directives are correctly defined and present", () => {
      expect(BASE_CSP_DIRECTIVES["default-src"]).toContain("'self'");
      expect(BASE_CSP_DIRECTIVES["script-src"]).toContain("'self'");
      expect(BASE_CSP_DIRECTIVES["connect-src"]).toContain("'self'");
      expect(BASE_CSP_DIRECTIVES["connect-src"]).toContain("https://*.stellar.org");
    });

    it("verifies STRICT_CSP_DIRECTIVES contains all required directives and domains", () => {
      expect(STRICT_CSP_DIRECTIVES["default-src"]).toEqual(["'self'"]);
      expect(STRICT_CSP_DIRECTIVES["script-src"]).toEqual(["'self'", "https://telegram.org"]);
      expect(STRICT_CSP_DIRECTIVES["connect-src"]).toContain("https://*.stellar.org");
      expect(STRICT_CSP_DIRECTIVES["connect-src"]).toContain("https://albedo.link");
      expect(STRICT_CSP_DIRECTIVES["connect-src"]).toContain("https://stellar.expert");
      expect(STRICT_CSP_DIRECTIVES["object-src"]).toEqual(["'none'"]);
      expect(STRICT_CSP_DIRECTIVES["base-uri"]).toEqual(["'self'"]);
      expect(STRICT_CSP_DIRECTIVES["form-action"]).toEqual(["'self'"]);
      expect(STRICT_CSP_DIRECTIVES["frame-ancestors"]).toEqual(["'none'"]);

      const validation = validateCspHeader(STATIC_CSP_HEADER);
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it("verifies vercel.json exactly matches STATIC_CSP_HEADER", () => {
      const vercelConfig = JSON.parse(vercelConfigRaw);
      const rootHeaders = vercelConfig.headers?.[0]?.headers || [];
      const cspEntry = rootHeaders.find(
        (h: { key: string; value: string }) => h.key === "Content-Security-Policy",
      );

      expect(cspEntry).toBeDefined();
      expect(cspEntry.value).toBe(STATIC_CSP_HEADER);
    });

    it("verifies nginx.conf exactly matches STATIC_CSP_HEADER", () => {
      const nginxMatch = nginxContent.match(
        /add_header\s+Content-Security-Policy\s+"([^"]+)"\s+always;/,
      );
      expect(nginxMatch).not.toBeNull();
      const extractedNginxCsp = nginxMatch ? nginxMatch[1] : "";
      expect(extractedNginxCsp).toBe(STATIC_CSP_HEADER);
    });

    it("verifies vite.config.ts uses STATIC_CSP_HEADER for preview and omits from server", () => {
      // preview must configure Content-Security-Policy
      expect(viteContent).toMatch(
        /preview:\s*\{\s*headers:\s*\{\s*["']Content-Security-Policy["']:\s*STATIC_CSP_HEADER/,
      );
      // server must NOT define strict Content-Security-Policy to avoid breaking React Refresh preamble and Tailwind dev styles
      expect(viteContent).not.toMatch(
        /server:\s*\{\s*headers:\s*\{\s*["']Content-Security-Policy["']/,
      );
    });
  });

  describe("2. Prohibited Directives (No unsafe-inline or unsafe-eval)", () => {
    it("verifies no 'unsafe-inline' appears in STATIC_CSP_HEADER", () => {
      expect(STATIC_CSP_HEADER).not.toContain("unsafe-inline");
      expect(STATIC_CSP_HEADER).not.toContain("'unsafe-inline'");
    });

    it("verifies no 'unsafe-eval' appears in STATIC_CSP_HEADER", () => {
      expect(STATIC_CSP_HEADER).not.toContain("unsafe-eval");
      expect(STATIC_CSP_HEADER).not.toContain("'unsafe-eval'");
    });

    it("verifies no 'unsafe-inline' or 'unsafe-eval' in vercel.json", () => {
      expect(vercelConfigRaw).not.toContain("unsafe-inline");
      expect(vercelConfigRaw).not.toContain("unsafe-eval");
    });

    it("verifies no 'unsafe-inline' or 'unsafe-eval' in nginx.conf", () => {
      expect(nginxContent).not.toContain("unsafe-inline");
      expect(nginxContent).not.toContain("unsafe-eval");
    });

    it("verifies buildCspHeader sanitizes any accidental unsafe tokens", () => {
      const dangerousDirectives = {
        "script-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        "style-src": ["'self'", "'unsafe-inline'"],
      };

      const sanitizedHeader = buildCspHeader({ directives: dangerousDirectives });
      expect(sanitizedHeader).not.toContain("unsafe-inline");
      expect(sanitizedHeader).not.toContain("unsafe-eval");
      expect(sanitizedHeader).toContain("script-src 'self'");
      expect(sanitizedHeader).toContain("style-src 'self'");
    });
  });

  describe("3. Cryptographic Nonce Generation & Per-Request Uniqueness", () => {
    it("generates valid cryptographically secure nonces", () => {
      const nonce = generateNonce();
      expect(typeof nonce).toBe("string");
      expect(nonce.length).toBeGreaterThanOrEqual(16);
      // Valid Base64 format
      expect(/^[A-Za-z0-9+/=]+$/.test(nonce)).toBe(true);
    });

    it("verifies nonces are strictly unique per request (100 sequential requests)", () => {
      const nonces = new Set<string>();
      const iterations = 100;

      for (let i = 0; i < iterations; i++) {
        const nonce = generateNonce();
        expect(nonces.has(nonce)).toBe(false);
        nonces.add(nonce);
      }

      expect(nonces.size).toBe(iterations);
    });

    it("correctly injects nonce token into script-src in buildCspHeader", () => {
      const nonce = generateNonce();
      const headerWithNonce = buildCspHeader({ nonce });

      expect(headerWithNonce).toContain(`'nonce-${nonce}'`);
      expect(headerWithNonce).toContain(`script-src 'self' https://telegram.org 'nonce-${nonce}'`);
      expect(headerWithNonce).not.toContain("unsafe-inline");
      expect(headerWithNonce).not.toContain("unsafe-eval");
    });

    it("throws a clear error if cryptographically secure random number generator is unavailable", () => {
      const originalCrypto = globalThis.crypto;
      try {
        // Temporarily redefine crypto to simulate an environment lacking getRandomValues
        Object.defineProperty(globalThis, "crypto", {
          value: undefined,
          writable: true,
          configurable: true,
        });

        expect(() => generateNonce()).toThrow(
          "Cryptographically secure random number generator is unavailable.",
        );
      } finally {
        Object.defineProperty(globalThis, "crypto", {
          value: originalCrypto,
          writable: true,
          configurable: true,
        });
      }
    });
  });

  describe("4. Domain Allowlist & Subresource Integrity (SRI) Audit", () => {
    it("documents all external domains with clear justifications", () => {
      expect(DOMAIN_ALLOWLIST_DOCUMENTATION.length).toBeGreaterThan(0);

      const auditedDomains = DOMAIN_ALLOWLIST_DOCUMENTATION.map((d) => d.domain);
      expect(auditedDomains).toContain("https://telegram.org");
      expect(auditedDomains).toContain("https://*.stellar.org");
      expect(auditedDomains).toContain("https://albedo.link");
      expect(auditedDomains).toContain("https://stellar.expert");
      expect(auditedDomains).toContain("https://xbull.app");
      expect(auditedDomains).toContain("https://images.unsplash.com");
      expect(auditedDomains).toContain("https://i.pravatar.cc");

      for (const entry of DOMAIN_ALLOWLIST_DOCUMENTATION) {
        expect(entry.reason).toBeTruthy();
        expect(entry.directive).toBeTruthy();
      }
    });

    it("verifies external scripts in index.html possess valid Subresource Integrity hashes and crossorigin", () => {
      // Find all external <script> tags with src="https://..."
      const scriptRegex = /<script\b([^>]*)src=["'](https?:\/\/[^"']+)["']([^>]*)>/gi;
      let match: RegExpExecArray | null;
      let externalScriptCount = 0;

      while ((match = scriptRegex.exec(indexHtmlContent)) !== null) {
        externalScriptCount++;
        const fullTag = match[0];
        const srcUrl = match[2];

        // Ensure every external script tag includes an integrity attribute
        expect(fullTag).toContain('integrity="sha384-');
        // Ensure integrity hash is valid sha384 base64 format (48 bytes base64-encoded = 64 chars)
        const integrityMatch = fullTag.match(/integrity=["'](sha384-[A-Za-z0-9+/=]{64})["']/);
        expect(integrityMatch).not.toBeNull();

        // Ensure crossorigin attribute is present
        expect(fullTag).toContain('crossorigin="anonymous"');

        // Documented domain
        expect(srcUrl).toContain("https://telegram.org");
      }

      // Assert at least one external script was audited
      expect(externalScriptCount).toBeGreaterThanOrEqual(1);
    });

    it("verifies no external stylesheets lack integrity attributes in index.html", () => {
      expect(indexHtmlContent).not.toMatch(
        /<link[^>]+rel=["']stylesheet["'][^>]+href=["']https?:\/\/(?!.*integrity=)/i,
      );
    });
  });
});
