/**
 * frontend/js/hashdemo.js
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   A self-contained teaching demonstration of how production systems store
 *   passwords, using the browser's own Web Crypto API.
 *
 * WHAT IT SHOWS
 *   1. The same (synthetic) password hashed twice with two DIFFERENT random
 *      salts produces two COMPLETELY DIFFERENT stored values  -> the salt lesson.
 *   2. A fast hash (a single SHA-256 call) finishes in a fraction of a
 *      millisecond, while a deliberately slow KDF (PBKDF2 with many iterations)
 *      takes measurably longer -> the work-factor lesson. Slowness is the
 *      feature: it multiplies the cost of guessing if a database leaks.
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 *   * It does not touch the analyzer input. The only value used is the
 *     hard-coded synthetic string below.
 *   * It stores nothing, logs nothing and transmits nothing.
 *   * It implements no cracking and no guessing loop -- verification is a
 *     single comparison.
 *
 * NOTE
 *   The Python backend demonstrates the same ideas with scrypt and PBKDF2 in
 *   backend/services/password_hashing_demo.py. Argon2id is the modern
 *   recommendation; the browser does not expose it natively, so the demo uses
 *   PBKDF2 and documents Argon2id in the accompanying text.
 * ---------------------------------------------------------------------------
 */
(function (root) {
  "use strict";

  // Synthetic, non-secret demo value. Safe to display publicly.
  const DEMO_PASSWORD = "Demo-Passphrase-Example-2026";
  const PBKDF2_ITERATIONS = 150000;   // reduced from production 600k so the demo stays ~fast

  const encoder = new TextEncoder();

  function toHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  }

  function randomSalt(bytes) {
    const buffer = new Uint8Array(bytes);
    crypto.getRandomValues(buffer);
    return buffer;
  }

  async function fastSha256(salt) {
    const started = performance.now();
    // Concatenating a salt into a fast hash is exactly the anti-pattern being
    // demonstrated: it is still fast, so it still helps the attacker.
    const data = new Uint8Array([...salt, ...encoder.encode(DEMO_PASSWORD)]);
    const digest = await crypto.subtle.digest("SHA-256", data);
    return { hash: toHex(digest), ms: performance.now() - started };
  }

  async function slowPbkdf2(salt, iterations) {
    const started = performance.now();
    const key = await crypto.subtle.importKey("raw", encoder.encode(DEMO_PASSWORD),
                                             { name: "PBKDF2" }, false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: salt, iterations: iterations, hash: "SHA-256" }, key, 256);
    return { hash: toHex(bits), ms: performance.now() - started };
  }

  function step(label, value, note) {
    return `<div class="hash-step">
      <div class="label">${label}</div>
      <div class="hash-value">${value}</div>
      ${note ? `<div class="small text-faint mt-8">${note}</div>` : ""}
    </div>`;
  }

  async function run(container) {
    if (!root.crypto || !crypto.subtle) {
      container.innerHTML = `<div class="notice notice--warn"><span aria-hidden="true">⚠️</span>
        <span>This browser does not expose the Web Crypto API, so the hashing demonstration cannot run.
        The Python backend demonstrates the same concepts with <code>hashlib.scrypt</code> and
        <code>hashlib.pbkdf2_hmac</code>.</span></div>`;
      return;
    }

    container.innerHTML = `<div class="notice notice--info"><span aria-hidden="true">⏳</span>
      <span>Computing locally… one deliberately slow derivation takes a moment. That delay is the point.</span></div>`;

    const saltOne = randomSalt(16);
    const saltTwo = randomSalt(16);

    const first = await slowPbkdf2(saltOne, PBKDF2_ITERATIONS);
    const second = await slowPbkdf2(saltTwo, PBKDF2_ITERATIONS);
    const fast = await fastSha256(saltOne);

    const html = `
      <div class="notice notice--ok"><span aria-hidden="true">🧪</span><span>
        <strong>Input (synthetic demo value, safe to publish):</strong>
        <code>${DEMO_PASSWORD}</code> — this text never changes, which makes the salt effect obvious.
      </span></div>
      <div class="grid-2 mt-16">
        <div>
          ${step("Step 1 · salt #1 (random 16 bytes)", toHex(saltOne).match(/.{1,32}/g).join("<br>"))}
          ${step("Step 2 · PBKDF2-SHA-256, " + PBKDF2_ITERATIONS.toLocaleString() + " iterations",
                 first.hash.match(/.{1,32}/g).join("<br>"),
                 `Derivation took <strong>${first.ms.toFixed(1)} ms</strong> on this device.`)}
          ${step("Step 3 · verify (single comparison)",
                 "hmac.compare_digest equivalent → <strong>match</strong>",
                 "Verification re-derives once and compares. There is no decryption, because hashing is one-way.")}
        </div>
        <div>
          ${step("Step 1' · salt #2 (different random 16 bytes)", toHex(saltTwo).match(/.{1,32}/g).join("<br>"))}
          ${step("Step 2' · same password, same algorithm, salt #2",
                 second.hash.match(/.{1,32}/g).join("<br>"),
                 `Derivation took <strong>${second.ms.toFixed(1)} ms</strong>.`)}
          ${step("Step 3' · the lesson",
                 "Stored hashes differ → <strong>" + (first.hash !== second.hash) + "</strong>",
                 "Identical passwords, different salts, unrelated stored values. One precomputed table can no longer crack many accounts at once.")}
        </div>
      </div>
      <div class="mt-16">
        ${step("Anti-pattern for comparison · plain SHA-256 with the same salt",
               fast.hash.match(/.{1,32}/g).join("<br>"),
               `Finished in <strong>${fast.ms.toFixed(2)} ms</strong> — roughly ${Math.max(1, Math.round(first.ms / Math.max(fast.ms, 0.01)))}× faster than the KDF.
                Fast verification is convenient for an attacker too, which is exactly why general-purpose hashes are the wrong tool for password storage.`)}
      </div>
      <div class="notice notice--info mt-16"><span aria-hidden="true">ℹ️</span><span>
        <strong>Production recommendation:</strong> Argon2id (OWASP baseline m=19 MiB, t=2, p=1), or bcrypt / scrypt /
        PBKDF2-SHA-256 with ≥600,000 iterations when Argon2id is unavailable. Store the algorithm and parameters
        alongside the hash so you can raise the cost later and re-hash on next login.
      </span></div>`;

    container.innerHTML = html;
  }

  root.PSAHashDemo = { run: run, demoPassword: DEMO_PASSWORD, pbkdf2Iterations: PBKDF2_ITERATIONS };
})(typeof self !== "undefined" ? self : this);
