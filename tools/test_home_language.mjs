// Dependency-free tests for static-page language preference and safe navigation.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

const code = readFileSync(new URL("../docs/home.js", import.meta.url), "utf8");
function boot({ path = "/inferenceIO/", language = "zh-CN", stored = null, blocked = false } = {}) {
  let preference = stored, redirected = null;
  const links = ["zh", "en"].map(value => ({
    dataset: { language: value }, href: "", listeners: {},
    addEventListener(event, listener) { this.listeners[event] = listener; },
  }));
  const window = {
    listeners: {},
    addEventListener(event, listener) { this.listeners[event] = listener; },
    location: { href: `https://example.test${path}`, replace(url) { redirected = url; } },
    localStorage: {
      getItem() { if (blocked) throw Error("storage denied"); return preference; },
      setItem(key, value) { if (blocked) throw Error("storage denied"); preference = value; },
    },
  };
  runInNewContext(code, { window, URL, document: {
    documentElement: { lang: language }, querySelectorAll: () => links,
  } });
  return { links, window, get preferred() { return preference; }, redirected };
}

assert.equal(boot().redirected, null, "first visit stays Chinese");
assert.equal(boot({ stored: "en" }).redirected, "https://example.test/inferenceIO/index.en.html?lang=en");
assert.equal(boot({ stored: "invalid" }).redirected, null);
assert.equal(boot({ stored: "en", path: "/inferenceIO/?lang=zh" }).redirected, null);
assert.equal(boot({ stored: "en", path: "/inferenceIO/?lang=zh" }).preferred, "zh");
assert.equal(boot({ path: "/inferenceIO/?lang=en&ref=docs#evidence" }).redirected,
  "https://example.test/inferenceIO/index.en.html?lang=en&ref=docs#evidence");
assert.equal(boot({ language: "en", stored: "zh", path: "/inferenceIO/index.en.html" }).redirected, null,
  "explicit English page does not redirect back");
assert.equal(boot({ language: "en", path: "/inferenceIO/index.en.html?lang=zh#navigate" }).redirected,
  "https://example.test/inferenceIO/?lang=zh#navigate");
assert.equal(boot({ stored: "en", path: "/inferenceIO/?lang=invalid" }).redirected, null);
assert.equal(boot({ blocked: true }).redirected, null);
const normal = boot({ path: "/inferenceIO/?ref=docs#evidence" });
assert.equal(normal.links[1].href, "https://example.test/inferenceIO/index.en.html?ref=docs&lang=en#evidence");
normal.links[1].listeners.click({ button: 0 });
assert.equal(normal.preferred, "en");
normal.links[0].listeners.click({ button: 0, ctrlKey: true });
assert.equal(normal.preferred, "en", "opening another tab does not change the current preference");
const denied = boot({ blocked: true });
assert.doesNotThrow(() => denied.links[1].listeners.click({ button: 0 }));
normal.window.location.href = "https://example.test/inferenceIO/?ref=docs#architecture";
normal.window.listeners.hashchange();
assert.equal(new URL(normal.links[1].href).hash, "#architecture", "language switch follows in-page navigation");
normal.window.location.href = "https://example.test/inferenceIO/?ref=docs#navigate";
normal.window.listeners.popstate();
assert.equal(new URL(normal.links[1].href).hash, "#navigate", "language switch follows history navigation");
console.log("PASS: 16 language navigation assertions, including denied storage and deep links");
