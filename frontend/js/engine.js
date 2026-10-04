/**
 * frontend/js/engine.js
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   A faithful JavaScript port of the Python analysis engine, so the site can
 *   be deployed as a static GitHub Pages app where EVERY analysis happens in
 *   the visitor's browser. Nothing is sent anywhere -- there is no backend to
 *   send it to.
 *
 * HOW PARITY IS PROVEN
 *   scripts/generate_fixtures.py runs the PYTHON engine over a list of demo
 *   passwords and writes tests/fixtures/expected_results.json.
 *   tests/js/run_parity_test.js then runs THIS engine over the same list in
 *   Node and compares score + classification + finding types.
 *   Both suites are wired into .github/workflows/ci.yml, so a divergence fails
 *   the build instead of silently misleading a user.
 *
 * PRIVACY
 *   * No network calls of any kind (no fetch, no XHR, no beacon).
 *   * The password is never written to console, storage or any DOM attribute
 *     other than the password input itself.
 *   * Every "evidence" string is masked with bullet characters.
 *
 * NOTE ON SHA-1
 *   The breach check hashes with SHA-1 because that is the convention used by
 *   the public breached-password range APIs, and the comparison happens
 *   against a bundled demo corpus. SHA-1 here is NOT used to store a password
 *   -- no password is stored at all -- so its known collision weaknesses do
 *   not apply to this use case. Password *storage* uses scrypt/PBKDF2/Argon2id,
 *   demonstrated separately in the hashing panel and in the Python module
 *   backend/services/password_hashing_demo.py.
 * ---------------------------------------------------------------------------
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./data/common_passwords.js"),
                             require("./data/keyboard_patterns.js"),
                             require("./data/common_phrases.js"),
                             require("./data/passphrase_words.js"));
  } else {
    root.PSAEngine = factory();
  }
})(typeof self !== "undefined" ? self : this, function (injected) {
  "use strict";

  /* =====================================================================
   * 0. DATA
   * ===================================================================== */
  const DATA = (typeof window !== "undefined" && window.PSA_DATA) ? window.PSA_DATA : {};
  const COMMON_PASSWORDS = new Set(
    (DATA.commonPasswords || injected || []).map((w) => String(w).toLowerCase())
  );
  const KEYBOARD_PATTERNS = (DATA.keyboardPatterns || []).map((w) => String(w).toLowerCase());
  const COMMON_PHRASES = new Set((DATA.commonPhrases || []).map(normalisePhrase));
  const PASSPHRASE_WORDS = (DATA.passphraseWords || []).filter((w) => /^[a-z]+$/i.test(w));

  // Dictionary = common passwords + generator word list, only tokens >= 4 chars.
  const DICTIONARY = new Set();
  COMMON_PASSWORDS.forEach((w) => { if (w.length >= 4) DICTIONARY.add(w); });
  PASSPHRASE_WORDS.forEach((w) => { const lw = w.toLowerCase(); if (lw.length >= 4) DICTIONARY.add(lw); });

  /* =====================================================================
   * 1. CONSTANTS (kept identical to the Python modules)
   * ===================================================================== */
  const WEIGHTS = {
    length: 35, diversity: 15, uniqueness: 10,
    pattern_resistance: 20, not_common: 10, unpredictability: 10
  };

  const BANDS = [
    [0, 20, "VERY WEAK", "This password would be guessed almost immediately."],
    [21, 40, "WEAK", "Better than nothing, but it will not survive a targeted or automated attack."],
    [41, 60, "MODERATE", "Reasonable for a throwaway account, not for email, banking or work."],
    [61, 80, "STRONG", "Good, provided it is unique to this one account and MFA is enabled."],
    [81, 100, "VERY STRONG", "Excellent, provided it is unique and stored in a password manager."]
  ];

  const LENGTH_BANDS = [
    [0, 0, "Empty", "No password entered.", 0.0],
    [1, 7, "Very short", "Below the minimum used by any modern guidance.", 0.05],
    [8, 11, "Short", "Acceptable only for low-value accounts, and even then it is risky.", 0.40],
    [12, 15, "Better length", "Meets the common 12-character modern baseline.", 0.72],
    [16, 19, "Strong length", "16+ characters is where length starts to carry real weight.", 0.92],
    [20, 1e5, "Excellent length", "Very strong length contribution -- keep it unpredictable too.", 1.00]
  ];

  const PENALTY_CAPS = {
    common_password: 45, common_phrase: 45, breach: 45, keyboard_pattern: 15,
    sequence: 15, repeated_characters: 15, repeated_substring: 15, personal_info: 20,
    predictable_structure: 15, year_pattern: 8, date_pattern: 8, phone_pattern: 10,
    dictionary_word: 12, short_length: 10, low_variety: 6, passphrase_structure: 0
  };

  const SEVERITY_FRACTION = { critical: 1.0, high: 0.85, medium: 0.55, low: 0.3, info: 0.1 };
  const SEVERITY_BITS = { critical: 30, high: 18, medium: 10, low: 5, info: 1 };

  const COMMON_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/\\`~";
  const SYMBOL_POOL = 33, LOWER_POOL = 26, UPPER_POOL = 26, DIGIT_POOL = 10;

  const MIN_SEQUENCE_LEN = 4, MIN_REPEAT_LEN = 4, MIN_KEYBOARD_LEN = 4,
        MIN_DICT_WORD_LEN = 4, MIN_CONTEXT_LEN = 3, MAX_LENGTH = 256;

  const KEYBOARD_ROWS = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"];
  const KEYBOARD_ROW_NAMES = {
    0: "number row", 1: "top letter row (qwertyuiop)",
    2: "home row (asdfghjkl)", 3: "bottom row (zxcvbnm)"
  };

  const LEET_MAP = {
    "4": "a", "@": "a", "8": "b", "3": "e", "6": "g", "9": "g", "1": "i",
    "!": "i", "|": "i", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t", "2": "z"
  };

  const SHIFT_MAP = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7",
    "*": "8", "(": "9", ")": "0", "_": "-", "+": "=", "~": "`", "{": "[",
    "}": "]", "|": "\\", ":": ";", "\"": "'", "<": ",", ">": ".", "?": "/"
  };

  const YEAR_RE = /(19\d{2}|20\d{2})/;
  const DATE_RE = /(\d{2,4}[-/.]\d{1,2}[-/.]\d{1,4})/;
  const PHONE_RE = /(?:\+?\d[\s-]?){9,}/;
  const PADDED_WORD_RE = /^[a-z]{3,}[0-9]{1,4}[!@#$%^&*_.-]?$/i;
  const WORD_WORD_NUMBER_RE = /^[a-z]{3,}[^a-z0-9]{1,2}[a-z]{3,}[^a-z0-9]{1,2}[0-9]{1,4}[^a-z0-9]{0,2}$/i;
  const ROTATED_RE = /^[a-z]{3,}[!@#$%^&*_.-]{1,3}[0-9]{1,4}$/i;
  const SEPARATORS_RE = /[\s._\-+]+/g;

  /* =====================================================================
   * 2. HELPERS
   * ===================================================================== */
  function mask(value) { return "\u2022".repeat(String(value).length); }

  function normalisePhrase(text) {
    return String(text).toLowerCase().replace(/[\s._\-+]+/g, " ").trim();
  }

  function finding(type, severity, title, description, evidence, positions) {
    return {
      type: type, severity: severity, title: title, description: description,
      evidence: evidence || "", positions: positions || [],
      penalty_bits: SEVERITY_BITS[severity]
    };
  }

  function unshift(text) {
    return Array.from(String(text)).map((ch) => SHIFT_MAP[ch] || ch.toLowerCase()).join("");
  }

  function deleet(text) {
    return Array.from(String(text)).map((ch) => {
      const lower = ch.toLowerCase();
      return LEET_MAP[lower] !== undefined ? LEET_MAP[lower] : ch;
    }).join("");
  }

  // Unicode-aware, mirroring Python's str.islower() / str.isupper() / str.isdigit()
  // so that non-Latin passwords ("пароль123") are classified the same way.
  function isLower(ch) {
    return typeof ch === "string" && ch.length > 0 &&
           ch !== ch.toUpperCase() && ch === ch.toLowerCase();
  }
  function isUpper(ch) {
    return typeof ch === "string" && ch.length > 0 &&
           ch !== ch.toLowerCase() && ch === ch.toUpperCase();
  }
  function isDigit(ch) {
    return /^\p{Nd}$/u.test(ch || "");
  }

  /* =====================================================================
   * 3. LENGTH ANALYSIS
   * ===================================================================== */
  function analyzeLength(password) {
    const text = password || "";
    const length = Array.from(text).length;
    let band = "Empty", guidance = "No password entered.", credit = 0.0;
    for (const [low, high, label, text2, fraction] of LENGTH_BANDS) {
      if (length >= low && length <= high) { band = label; guidance = text2; credit = fraction; break; }
    }
    return {
      length: length, band: band, credit: credit, guidance: guidance,
      is_empty: length === 0, is_recommended_length: length >= 12,
      is_very_long: length >= 20, max_supported_length: MAX_LENGTH,
      recommended_minimum: 12,
      note: "Length is the single most useful lever you control, because each extra character " +
            "multiplies an attacker's work. It is not sufficient on its own: 20 repeated " +
            "characters are still trivially guessable."
    };
  }

  /* =====================================================================
   * 4. CHARACTER ANALYSIS
   * ===================================================================== */
  function analyzeCharacters(password) {
    const text = String(password || "");
    const chars = Array.from(text);
    const length = chars.length;
    const hasLower = chars.some(isLower);
    const hasUpper = chars.some(isUpper);
    const hasDigit = chars.some(isDigit);
    const hasSymbol = chars.some((c) => COMMON_SYMBOLS.indexOf(c) !== -1);
    const hasSpace = chars.some((c) => c === " ");
    const hasUnicode = chars.some((c) => c.codePointAt(0) > 127);
    const typeCount = [hasLower, hasUpper, hasDigit, hasSymbol, hasSpace].filter(Boolean).length;
    const uniqueCount = new Set(chars).size;
    const ratio = length ? uniqueCount / length : 0;
    const types = [];
    if (hasLower) types.push("lowercase");
    if (hasUpper) types.push("uppercase");
    if (hasDigit) types.push("digits");
    if (hasSymbol) types.push("symbols");
    if (hasSpace) types.push("spaces");
    return {
      length: length, has_lowercase: hasLower, has_uppercase: hasUpper, has_digits: hasDigit,
      has_symbols: hasSymbol, has_spaces: hasSpace, has_unicode: hasUnicode,
      character_type_count: typeCount, character_types: types,
      unique_character_count: uniqueCount, unique_character_ratio: Math.round(ratio * 1000) / 1000,
      repeated_character_count: length - uniqueCount,
      caveat: "Character diversity is useful but weak on its own: a single common word with a " +
              "capital letter and a trailing digit satisfies every composition rule while " +
              "remaining one of the most predictable shapes in existence."
    };
  }

  function varietyCredit(chars, lengthReport) {
    let typeCredit = Math.min(chars.character_type_count / 4, 1) * 0.6;
    const ratioCredit = Math.min(chars.unique_character_ratio / 0.8, 1) * 0.4;
    if (lengthReport.length < 8) typeCredit *= 0.5;
    return Math.round((typeCredit + ratioCredit) * 1000) / 1000;
  }

  /* =====================================================================
   * 5. ENTROPY
   * ===================================================================== */
  function estimatePoolSize(password) {
    const chars = Array.from(String(password || ""));
    if (!chars.length) return 0;
    let pool = 0;
    if (chars.some(isLower)) pool += LOWER_POOL;
    if (chars.some(isUpper)) pool += UPPER_POOL;
    if (chars.some(isDigit)) pool += DIGIT_POOL;
    if (chars.some((c) => COMMON_SYMBOLS.indexOf(c) !== -1)) pool += SYMBOL_POOL;
    if (chars.some((c) => c === " ")) pool += 1;
    if (chars.some((c) => c.codePointAt(0) > 127)) pool += 100;
    return Math.max(pool, 1);
  }

  function theoreticalEntropy(password, pool) {
    if (!password) return 0;
    const p = pool || estimatePoolSize(password);
    return Array.from(password).length * Math.log2(p);
  }

  function shannonEntropy(password) {
    const chars = Array.from(password || "");
    if (!chars.length) return 0;
    const counts = new Map();
    chars.forEach((c) => counts.set(c, (counts.get(c) || 0) + 1));
    let perChar = 0;
    counts.forEach((count) => {
      const p = count / chars.length;
      perChar -= p * Math.log2(p);
    });
    return perChar * chars.length;
  }

  function passphraseEntropyBits(wordCount, listSize) {
    const size = listSize || Math.max(PASSPHRASE_WORDS.length, 2);
    return wordCount * Math.log2(size);
  }

  function humaniseSeconds(seconds) {
    if (seconds < 1) return "well under a second";
    const units = [["seconds", 60], ["minutes", 60], ["hours", 24], ["days", 365],
                   ["years", 1000], ["thousand years", 1000], ["million years", 1000],
                   ["billion years", 1000]];
    let value = seconds, label = "seconds";
    for (const [nextLabel, divisor] of units) {
      if (value < divisor) {
        const rounded = value >= 100 ? Math.round(value).toLocaleString() : value.toFixed(1);
        return rounded + " " + label;
      }
      value /= divisor; label = nextLabel;
    }
    return "far beyond the age of the universe";
  }

  function estimateGuessResistance(bits) {
    const rates = [
      ["online_throttled", 10, "Online, rate-limited login form"],
      ["offline_slow_hash", 1e5, "Offline attack on a slow hash (Argon2id/bcrypt)"],
      ["offline_fast_hash", 1e11, "Offline attack on a fast hash (unsalted MD5/SHA-1)"]
    ];
    const attempts = bits > 0 ? Math.pow(2, bits - 1) : 1;
    const scenarios = rates.map(([key, rate, label]) => ({
      key: key, label: label, guesses_per_second: rate,
      estimate: bits <= 0 ? "Instant" : humaniseSeconds(attempts / rate)
    }));
    return {
      estimate_label: "Educational estimate only -- not a guaranteed crack time",
      scenarios: scenarios,
      half_search_space: attempts,
      caveat: "Real guessing resistance depends on the attacker model (online vs offline), the " +
              "hash function and its work factor, rate limiting and lockout, whether a hash " +
              "database has already leaked, and whether this password is reused elsewhere."
    };
  }

  function entropyReport(password, patternPenaltyBits) {
    const pool = estimatePoolSize(password);
    const theoretical = theoreticalEntropy(password, pool);
    const effective = Math.max(theoretical - Math.abs(patternPenaltyBits || 0), 0);
    const words = String(password || "").toLowerCase().split(/[^a-z]+/).filter(Boolean);
    return {
      pool_size: pool,
      theoretical_bits: Math.round(theoretical * 10) / 10,
      effective_bits: Math.round(effective * 10) / 10,
      shannon_bits: Math.round(shannonEntropy(password) * 10) / 10,
      pattern_penalty_bits: Math.round(Math.abs(patternPenaltyBits || 0) * 10) / 10,
      is_passphrase_like: words.length >= 3 &&
        (/[ \-_]/.test(password || "")),
      passphrase_estimate_bits: Math.round(passphraseEntropyBits(Math.max(words.length, 1)) * 10) / 10,
      formula: "Entropy (theoretical) \u2248 length \u00d7 log2(pool size)",
      caveat: "Theoretical entropy assumes truly random character selection. Human-chosen " +
              "passwords are predictable, so this number is an upper bound. Effective bits " +
              "additionally subtract pattern, dictionary and context penalties."
    };
  }

  /* =====================================================================
   * 6. STRUCTURE
   * ===================================================================== */
  function analyzeStructure(password) {
    const text = String(password || "");
    const tokens = text.split(SEPARATORS_RE).filter(Boolean);
    const separators = Array.from(new Set(Array.from(text).filter((c) => /[\s._\-+\t]/.test(c))));
    const lengths = tokens.map((t) => t.length);
    const isPassphraseLike = tokens.length >= 4 && lengths.every((l) => l >= 3) && text.length >= 18;
    return {
      token_count: tokens.length,
      separators_used: separators,
      is_multi_word: tokens.length >= 3,
      is_passphrase_like: isPassphraseLike,
      average_token_length: lengths.length
        ? Math.round((lengths.reduce((a, b) => a + b, 0) / lengths.length) * 100) / 100 : 0,
      note: "A phrase of 4 or more separate words is scored as a passphrase: the value gains " +
            "length and independence from the words themselves, so individual dictionary " +
            "words are no longer treated as weaknesses."
    };
  }

  /* =====================================================================
   * 7. PATTERN DETECTION
   * ===================================================================== */
  function detectCommonPassword(password) {
    if (!password) return [];
    const candidate = password.toLowerCase();
    const normalised = deleet(password).toLowerCase();
    if (COMMON_PASSWORDS.has(candidate) || COMMON_PASSWORDS.has(normalised)) {
      return [finding("common_password", "critical", "Known common password",
        "Your password matches a commonly used password pattern and should not be used. " +
        "These strings are first in every attacker's list.", mask(password))];
    }
    return [];
  }

  function detectCommonPhrases(password) {
    if (!password || COMMON_PHRASES.size === 0) return [];
    const normalised = normalisePhrase(password);
    for (const phrase of COMMON_PHRASES) {
      if (phrase && normalised.indexOf(phrase) !== -1) {
        return [finding("common_phrase", "critical", "Famous / predictable phrase",
          "This password contains a well-known phrase or quote. Famous phrases are collected " +
          "in cracking wordlists, so length does not protect them. Choose your own unrelated " +
          "words instead of a quotation, lyric or proverb.", mask(password))];
      }
    }
    return [];
  }

  function detectDictionaryWords(password) {
    if (!password || password.length < MIN_DICT_WORD_LEN) return [];
    const candidates = [];
    [password.toLowerCase(), deleet(password).toLowerCase()].forEach((text, index) => {
      const baseHow = index === 0 ? "plain" : "after l33t substitution";
      text.split(/[^a-z]+/).forEach((token) => {
        if (token.length < MIN_DICT_WORD_LEN) return;
        if (DICTIONARY.has(token)) { candidates.push([token, baseHow]); return; }
        // Digit->letter substitutions can corrupt a word's tail (see the Python
        // engine): fall back to the longest dictionary prefix.
        for (let length = token.length; length >= MIN_DICT_WORD_LEN; length--) {
          const prefix = token.slice(0, length);
          if (DICTIONARY.has(prefix)) { candidates.push([prefix, baseHow + " (word prefix match)"]); break; }
        }
      });
    });
    const seen = new Set(), out = [];
    candidates.forEach(([token, how]) => {
      if (seen.has(token)) return;
      seen.add(token);
      out.push(finding("dictionary_word", token.length >= 6 ? "high" : "medium",
        "Common word detected",
        "A word from the common-word dictionary was found in your password (" + how + "). " +
        "Attackers try dictionary words, capitalisations and l33t variants before anything else.",
        mask(token)));
    });
    return out;
  }

  function findSequenceRuns(text, step) {
    const chars = Array.from(text);
    const runs = [];
    let start = 0;
    for (let i = 1; i <= chars.length; i++) {
      const continues = i < chars.length &&
        (chars[i].charCodeAt(0) - chars[i - 1].charCodeAt(0)) === step;
      if (!continues) {
        if (i - start >= MIN_SEQUENCE_LEN) runs.push([start, i]);
        start = i;
      }
    }
    return runs;
  }

  function detectSequences(password) {
    if (!password) return [];
    const lowered = password.toLowerCase();
    const chars = Array.from(lowered);
    const out = [];
    [[1, "ascending"], [-1, "descending"]].forEach(([step, direction]) => {
      findSequenceRuns(lowered, step).forEach(([start, end]) => {
        const span = chars.slice(start, end).join("");
        const isDigit = /^\d+$/.test(span);
        out.push(finding("sequence", span.length >= 5 ? "high" : "medium",
          "Predictable " + direction + " " + (isDigit ? "numeric" : "alphabetical") + " sequence",
          "A " + direction + " " + (isDigit ? "number" : "letter") + " run of " + span.length +
          " characters was found. Sequences reduce effective entropy because the attacker " +
          "guesses 'pattern + start + direction' instead of every character independently.",
          mask(span), rangeArray(start, end)));
      });
    });
    return out;
  }

  function rangeArray(start, end) {
    const arr = [];
    for (let i = start; i < end; i++) arr.push(i);
    return arr;
  }

  function detectKeyboardPatterns(password) {
    if (!password) return [];
    const lowered = password.toLowerCase();
    const physical = unshift(password);
    const haystacks = [lowered, physical];
    const out = [];

    const sorted = KEYBOARD_PATTERNS.slice().sort((a, b) => b.length - a.length);
    for (const fragment of sorted) {
      if (fragment.length < MIN_KEYBOARD_LEN) continue;
      for (const hay of haystacks) {
        if (hay.indexOf(fragment) !== -1) {
          const index = hay.indexOf(fragment);
          out.push(finding("keyboard_pattern", "high", "Keyboard walk detected",
            "A known keyboard sequence of " + fragment.length + " adjacent keys was found. " +
            "Keyboard walks are among the first patterns automated tools try because they are " +
            "easy to type and easy to guess.",
            mask(password.slice(index, index + fragment.length)),
            rangeArray(index, index + fragment.length)));
          return dedupe(out);
        }
      }
    }

    findSequenceRuns(physical, 1).forEach(([start, end]) => {
      const span = physical.slice(start, end);
      for (let rowIndex = 0; rowIndex < KEYBOARD_ROWS.length; rowIndex++) {
        const row = KEYBOARD_ROWS[rowIndex];
        if (Array.from(span).every((ch) => row.indexOf(ch) !== -1)) {
          out.push(finding("keyboard_pattern", "medium", "Keyboard row walk",
            "A run of " + span.length + " characters follows adjacent keys on the " +
            KEYBOARD_ROW_NAMES[rowIndex] + ". Attacker wordlists include these shapes with " +
            "every shift/case variation.",
            mask(password.slice(start, end)), rangeArray(start, end)));
          break;
        }
      }
    });

    // A reversed walk is not a descending code-point run ('y' is not one less
    // than 't'), so we test each keyboard row in both directions and look for
    // the longest matching run. Mirrors the Python implementation exactly.
    outer:
    for (const row of KEYBOARD_ROWS) {
      const sources = [[row, "Keyboard row walk"], [row.split("").reverse().join(""), "Reversed keyboard walk"]];
      for (const [source, label] of sources) {
        for (let startIndex = 0; startIndex < source.length; startIndex++) {
          for (let length = source.length - startIndex; length >= MIN_KEYBOARD_LEN; length--) {
            const candidate = source.substr(startIndex, length);
            const position = physical.indexOf(candidate);
            if (position !== -1) {
              out.push(finding("keyboard_pattern", "medium", label,
                "A run of adjacent keys read along a keyboard row was found. Reversing or " +
                "shifting a keyboard walk does not make it meaningfully harder to guess.",
                mask(password.slice(position, position + candidate.length)),
                rangeArray(position, position + candidate.length)));
              break outer;
            }
          }
        }
      }
    }

    return dedupe(out);
  }

  function detectRepetition(password) {
    if (!password) return [];
    const chars = Array.from(password);
    const out = [];

    // repeated single characters
    let runStart = 0;
    for (let i = 1; i <= chars.length; i++) {
      const same = i < chars.length && chars[i] === chars[i - 1];
      if (!same) {
        const runLength = i - runStart;
        if (runLength >= MIN_REPEAT_LEN) {
          const ch = chars[runStart];
          let kind = "symbol";
          if (isDigit(ch)) kind = "digit";
          else if (isLower(ch) || isUpper(ch)) kind = "letter";
          else if (ch === " ") kind = "space";
          out.push(finding("repeated_characters", runLength >= 6 ? "high" : "medium",
            "Repeated character run",
            "A repeated " + kind + " is repeated " + runLength + " times. Long runs collapse the " +
            "real search space: the attacker only needs to guess the pattern, not every character.",
            mask(chars.slice(runStart, i).join("")), rangeArray(runStart, i)));
        }
        runStart = i;
      }
    }

    // repeated substrings (largest blocks first)
    //
    // RULE A (exact): the same characters repeat ("abcabc", "121212").
    // RULE B (case echo): the same LETTERS repeat with a case change in at most
    //   one position ("Coco" = "Co" + "co"), because one capital cannot hide a
    //   repeat. It deliberately does NOT fire when the case pattern differs in
    //   several positions ("jdD" + "jDd"): that is different data, and the old
    //   lower-cased comparison reported it as a repeat, which invented false
    //   positives in random mixed-case values.
    // Noise control: above 20 characters a 2-character block must repeat at
    // least three times to count. Mirrors backend/services/pattern_detector.py.
    const caseEcho = (first, second) => {
      if (first.length !== second.length) return false;
      if (first.toLowerCase() !== second.toLowerCase()) return false;
      let differences = 0;
      for (let i = 0; i < first.length; i++) if (first[i] !== second[i]) differences++;
      return differences <= 1;
    };
    const length = chars.length;
    const reported = [];
    for (let size = Math.max(Math.floor(length / 2), 2); size >= 2; size--) {
      let start = 0;
      while (start + size * 2 <= length) {
        const block = chars.slice(start, start + size).join("");
        if (new Set(Array.from(block)).size === 1) { start++; continue; }
        let repeats = 1;
        while (chars.slice(start + repeats * size, start + (repeats + 1) * size).join("") === block) repeats++;
        if (repeats < 2) {
          const following = chars.slice(start + size, start + 2 * size).join("");
          if (/^[A-Za-z]+$/.test(block) && /^[A-Za-z]+$/.test(following) && caseEcho(block, following)) {
            repeats = 2;
          }
        }
        const tooShortARepeat = size <= 2 && repeats < 3 && length > 20;
        if (repeats >= 2 && !tooShortARepeat) {
          const spanEnd = start + repeats * size;
          const overlaps = reported.some(([s, e]) => start < e && spanEnd > s);
          if (!overlaps) {
            reported.push([start, spanEnd]);
            out.push(finding("repeated_substring", repeats >= 3 ? "high" : "medium",
              "Repeated block pattern",
              "A " + size + "-character block is repeated " + repeats + " times. Repeating a " +
              "block adds almost no unpredictability -- the string looks longer without being " +
              "harder to guess.",
              mask(chars.slice(start, spanEnd).join("")), rangeArray(start, spanEnd)));
          }
          start = spanEnd;
        } else { start++; }
      }
      if (reported.length >= 2) break;
    }
    return dedupe(out);
  }

  function detectPredictableStructure(password) {
    if (!password) return [];
    const out = [];
    if (PADDED_WORD_RE.test(password)) {
      out.push(finding("predictable_structure", "medium", "Common word + trailing number",
        "Your password looks like a memorable word plus a short number. Cracking tools " +
        "generate exactly this shape first: word lists crossed with years, 1234, and common " +
        "symbol endings.", mask(password)));
    } else if (WORD_WORD_NUMBER_RE.test(password)) {
      out.push(finding("predictable_structure", "medium", "Memorable words + trailing number",
        "Your password is built from recognisable words joined by separators and finished with " +
        "a short number. Attackers combine wordlists with separators and year/number suffixes, " +
        "so this shape is only marginally stronger than a single word.", mask(password)));
    } else if (ROTATED_RE.test(password)) {
      out.push(finding("predictable_structure", "medium", "Word + symbol + number shape",
        "Your password follows the well-known 'word + symbol + number' shape. It satisfies " +
        "composition rules while staying highly predictable.", mask(password)));
    }

    const yearMatch = password.match(YEAR_RE);
    if (yearMatch) {
      const year = parseInt(yearMatch[1], 10);
      const likelyBirthYear = year >= 1940 && year <= 2012;
      const index = password.indexOf(yearMatch[1]);
      out.push(finding("year_pattern", likelyBirthYear ? "medium" : "low",
        "Year-like number detected",
        "A " + (likelyBirthYear ? "plausible birth year" : "year-like number") + " (" +
        mask(yearMatch[1]) + ") appears in your password. Birth years and the current year are " +
        "among the most attempted numeric suffixes.",
        mask(yearMatch[1]), rangeArray(index, index + 4)));
    }

    const dateMatch = password.match(DATE_RE);
    if (dateMatch) {
      const index = password.indexOf(dateMatch[1]);
      out.push(finding("date_pattern", "medium", "Date-like pattern detected",
        "A date-shaped string was found. Birthdays and anniversaries are guessable from public " +
        "profile data and social media.", mask(dateMatch[1]),
        rangeArray(index, index + dateMatch[1].length)));
    }

    const phoneMatch = password.match(PHONE_RE);
    if (phoneMatch) {
      const index = password.indexOf(phoneMatch[0]);
      out.push(finding("phone_pattern", "medium", "Phone-like digit string detected",
        "A long digit string that looks like a phone number was found. Phone numbers are " +
        "identifiable information and appear in breach corpora used for targeted guessing.",
        mask(phoneMatch[0]), rangeArray(index, index + phoneMatch[0].length)));
    }
    return out;
  }

  function contextTokens(context) {
    if (!context) return [];
    const fields = ["first_name", "last_name", "username", "email", "birth_year",
                    "organisation", "company", "college"];
    const tokens = [];
    fields.forEach((field) => {
      const raw = String(context[field] || "").trim();
      if (!raw) return;
      if (field === "email") { tokens.push([field, raw.split("@")[0]]); return; }
      raw.split(/[\s._\-]+/).forEach((part) => { if (part) tokens.push([field, part]); });
    });
    return tokens.map(([field, token]) => [field, token.toLowerCase()])
                 .filter(([, token]) => token.length >= MIN_CONTEXT_LEN);
  }

  function detectPersonalInfo(password, context) {
    if (!password || !context) return [];
    const lowered = String(password).toLowerCase();
    const deleetLowered = deleet(password).toLowerCase();
    const out = [], seen = new Set();
    contextTokens(context).forEach(([field, token]) => {
      if (seen.has(token)) return;
      if (lowered.indexOf(token) !== -1 || deleetLowered.indexOf(token) !== -1) {
        seen.add(token);
        out.push(finding("personal_info", "high", "Personal information in password",
          "Your password appears to contain the " + field.replace(/_/g, " ") + " you provided. " +
          "Attackers use personal details from social media, breach dumps and company websites " +
          "to build targeted guesses.", mask(token)));
      }
    });
    return dedupe(out);
  }

  function sha1Hex(value) {
    // Compact SHA-1 implementation -- used ONLY for the local breach-corpus
    // comparison, mirroring the HIBP convention. Not used for password storage.
    function rotl(n, s) { return (n << s) | (n >>> (32 - s)); }
    const bytes = [];
    for (const ch of Array.from(value)) {
      const cp = ch.codePointAt(0);
      if (cp < 0x80) bytes.push(cp);
      else if (cp < 0x800) bytes.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
      else if (cp < 0x10000) bytes.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
      else bytes.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63),
                      0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    }
    const bitLen = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    for (let i = 7; i >= 0; i--) bytes.push((bitLen / Math.pow(2, i * 8)) & 0xff);

    let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    for (let offset = 0; offset < bytes.length; offset += 64) {
      const w = new Array(80).fill(0);
      for (let i = 0; i < 16; i++) {
        w[i] = (bytes[offset + i * 4] << 24) | (bytes[offset + i * 4 + 1] << 16) |
               (bytes[offset + i * 4 + 2] << 8) | bytes[offset + i * 4 + 3];
      }
      for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
      let a = h0, b = h1, c = h2, d = h3, e = h4;
      for (let i = 0; i < 80; i++) {
        let f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        const temp = (rotl(a, 5) + f + e + k + w[i]) | 0;
        e = d; d = c; c = rotl(b, 30); b = a; a = temp;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0;
      h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
    }
    return [h0, h1, h2, h3, h4]
      .map((n) => (n >>> 0).toString(16).padStart(8, "0")).join("").toUpperCase();
  }

  const BREACH_CORPUS = new Set([
    "123456", "password123", "qwerty123", "letmein", "welcome1", "admin123",
    "iloveyou1", "Password123!", "qwerty2026!", "hello1234", "summer2025",
    "password", "12345678", "qwerty", "iloveyou", "abc123", "sunshine", "monkey"
  ].map((p) => sha1Hex(p)));

  function detectBreach(password) {
    if (!password) return [];
    const digest = sha1Hex(password);
    if (!BREACH_CORPUS.has(digest)) return [];
    return [finding("breach", "critical", "Found in demo breach corpus",
      "This password appears in the bundled demo list of publicly known weak patterns. If a " +
      "real service reported this, the password must be changed immediately and never reused.",
      mask(password))];
  }

  function dedupe(findings) {
    const seen = new Set(), out = [];
    findings.forEach((f) => {
      const key = f.type + "|" + f.title + "|" + f.evidence;
      if (!seen.has(key)) { seen.add(key); out.push(f); }
    });
    return out;
  }

  function detectAllPatterns(password, context) {
    let findings = [];
    const structure = analyzeStructure(password);

    if (password) {
      findings = findings.concat(detectCommonPassword(password));
      findings = findings.concat(detectCommonPhrases(password));
      if (structure.is_passphrase_like) {
        findings.push(finding("passphrase_structure", "info", "Passphrase structure detected",
          "This value looks like a passphrase built from " + structure.token_count + " words. " +
          "Independent, randomly chosen words are a legitimate way to gain length, so the " +
          "individual words are not counted as weaknesses here.", mask(password)));
      } else {
        findings = findings.concat(detectDictionaryWords(password));
      }
      findings = findings.concat(detectSequences(password));
      findings = findings.concat(detectKeyboardPatterns(password));
      findings = findings.concat(detectRepetition(password));
      findings = findings.concat(detectPredictableStructure(password));
      findings = findings.concat(detectPersonalInfo(password, context));
      findings = findings.concat(detectBreach(password));
    }

    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort((a, b) => (order[a.severity] - order[b.severity]) ||
                            (b.penalty_bits - a.penalty_bits));

    const categories = {};
    findings.forEach((f) => { categories[f.type] = (categories[f.type] || 0) + 1; });

    return {
      findings: findings,
      pattern_penalty_bits: findings.reduce((sum, f) => sum + f.penalty_bits, 0),
      categories: categories,
      breach_prefix: password ? sha1Hex(password).slice(0, 5) : null,
      structure: structure
    };
  }

  /* =====================================================================
   * 8. SCORING
   * ===================================================================== */
  function classify(score) {
    for (const [low, high, label, summary] of BANDS) {
      if (score >= low && score <= high) return { classification: label, summary: summary, band: low + "-" + high };
    }
    return { classification: "VERY STRONG", summary: BANDS[BANDS.length - 1][3], band: "81-100" };
  }

  function patternPenaltyPoints(findings) {
    const perCategory = {};
    findings.forEach((f) => {
      const cap = PENALTY_CAPS[f.type] !== undefined ? PENALTY_CAPS[f.type] : 5;
      const fraction = SEVERITY_FRACTION[f.severity] !== undefined ? SEVERITY_FRACTION[f.severity] : 0.3;
      perCategory[f.type] = (perCategory[f.type] || 0) + cap * fraction;
    });
    const cappedRaw = {}, cappedDisplay = {};
    Object.entries(perCategory).forEach(([key, value]) => {
      const limit = PENALTY_CAPS[key] !== undefined ? PENALTY_CAPS[key] : 5;
      cappedRaw[key] = Math.min(value, limit);
      cappedDisplay[key] = Math.round(cappedRaw[key]);
    });
    // Python: int(round(sum(scaled_values))) -- the sum happens BEFORE rounding,
    // which is why the displayed per-category numbers can sum to one less.
    const total = pyRound(Object.values(cappedRaw).reduce((a, b) => a + b, 0));
    return [total, cappedDisplay];
  }

  function applicableCaps(password, findings, lengthReport, chars) {
    const types = new Set(findings.map((f) => f.type));
    const length = lengthReport.length;
    const unique = chars.unique_character_count;
    const hasLetters = chars.has_lowercase || chars.has_uppercase;
    const caps = [];
    const add = (cap, rule, reason) => caps.push({ cap: cap, rule: rule, reason: reason });

    if (length === 0) { add(0, "empty", "No value submitted."); return caps; }
    if (length <= 3) {
      add(10, "extremely_short", length + " character(s) is guessable instantly regardless of " +
        "which characters were used.");
    } else if (length < 8) {
      add(20, "too_short", length + " characters is below every modern minimum; no combination " +
        "of symbols fixes that.");
    }
    if (unique === 1 && length >= 8) {
      add(15, "single_repeated_character", "The entire value is one character repeated, so only " +
        "the length and the character need to be guessed.");
    } else if (unique <= 3 && length >= 6) {
      add(25, "very_low_uniqueness", "Only " + unique + " distinct characters are used across " +
        length + " positions, so the real search space is tiny.");
    }
    if (!hasLetters && length < 12) {
      add(35, "no_letters_short", "Digits/symbols only and under 12 characters: the pool may " +
        "look large, but the value is short enough to brute force.");
    }
    if (!hasLetters && length >= 12) {
      add(45, "no_letters", "Digits and symbols only: without letters the search pool is much " +
        "smaller than the character-space estimate implies, so the value is held below the " +
        "STRONG band.");
    }
    if (length >= 16 && unique <= 4) {
      add(45, "thin_character_set", "Only " + unique + " distinct characters are used across " +
        length + " positions, so the value is far more repetitive than its length suggests.");
    }
    if (length >= 16 && unique <= 3) {
      add(30, "thin_character_set_low", unique + " distinct characters repeated across " + length +
        " positions -- length cannot compensate for so little variety.");
    }
    if (length >= 16 && unique <= 2) {
      add(20, "extremely_thin_character_set", "Only " + unique + " distinct characters are used " +
        "across " + length + " positions.");
    }
    if (types.has("common_password") || types.has("breach") || types.has("common_phrase")) {
      add(20, "known_common_or_breached", "This value is a known common password, a known " +
        "phrase, or present in the demo breach corpus, so it is never allowed above the VERY " +
        "WEAK band.");
    }
    if (types.has("personal_info")) {
      add(40, "contains_personal_information", "The value contains personal information you " +
        "supplied. That information is discoverable from profiles and breach data, so the score " +
        "is held in the WEAK band.");
    }
    const wordLike = types.has("dictionary_word") || types.has("predictable_structure") ||
                     types.has("passphrase_structure");
    if (types.has("year_pattern") && wordLike) {
      add(45, "word_plus_year", "A recognisable word (or words) combined with a year is one of " +
        "the most-modelled attack shapes, so it is capped below the STRONG band.");
    } else if (types.has("predictable_structure") && types.has("dictionary_word")) {
      add(60, "word_plus_number_shape", "A memorable word combined with a short number is a " +
        "pattern attackers model explicitly, so it is capped below the STRONG band even when it " +
        "looks complex.");
    }
    return caps;
  }

  function scorePassword(password, findings) {
    const lengthReport = analyzeLength(password);
    const chars = analyzeCharacters(password);

    const lengthEarned = lengthReport.credit * WEIGHTS.length;
    const diversityEarned = varietyCredit(chars, lengthReport) * WEIGHTS.diversity;
    const uniquenessEarned = Math.min(chars.unique_character_ratio, 1) * WEIGHTS.uniqueness;

    const distinct = Array.from(new Set(findings.map((f) => f.type)));
    let patternLoss = 0;
    distinct.forEach((category) => {
      const worst = Math.max.apply(null, findings.filter((f) => f.type === category)
        .map((f) => f.penalty_bits));
      patternLoss += Math.min(worst / 30, 1) / Math.max(distinct.length, 1) * 1.6;
    });
    const patternEarned = Math.max(1 - patternLoss, 0) * WEIGHTS.pattern_resistance;

    const commonHit = findings.some((f) => f.type === "common_password");
    const breachHit = findings.some((f) => f.type === "breach");
    const notCommonEarned = (commonHit || breachHit) ? 0 : WEIGHTS.not_common;

    let unpredictability = 0;
    if (lengthReport.length >= 16) unpredictability += 0.5;
    if (lengthReport.length >= 20) unpredictability += 0.2;
    if (chars.character_type_count >= 3) unpredictability += 0.3;
    if (chars.unique_character_ratio >= 0.75) unpredictability += 0.2;
    if (chars.character_type_count >= 4) unpredictability += 0.2;
    if (findings.length === 0) unpredictability += 0.3;
    unpredictability = Math.min(unpredictability, 1) * WEIGHTS.unpredictability;

    const rawPositive = lengthEarned + diversityEarned + uniquenessEarned +
                        patternEarned + notCommonEarned + unpredictability;
    const [penalty, penaltyBreakdown] = patternPenaltyPoints(findings);

    if (!password) {
      return {
        score: 0, raw_score: 0, classification: "VERY WEAK", summary: "No password entered.",
        band: "0-20", cap_applied: null, caps: [],
        breakdown: {
          length: { earned: 0, max: WEIGHTS.length, detail: lengthReport.band },
          character_diversity: { earned: 0, max: WEIGHTS.diversity, detail: "none" },
          unique_character_ratio: { earned: 0, max: WEIGHTS.uniqueness, detail: "0%" },
          pattern_resistance: { earned: 0, max: WEIGHTS.pattern_resistance, detail: "n/a" },
          not_a_common_password: { earned: 0, max: WEIGHTS.not_common, detail: "n/a" },
          unpredictability: { earned: 0, max: WEIGHTS.unpredictability, detail: "n/a" }
        },
        penalties: { total: 0, by_category: {} }
      };
    }

    // Mirror of the Python engine: normalise float noise to 6 decimals before
    // the final half-to-even rounding, so both engines agree on boundaries.
    let score = roundTo(rawPositive - penalty, 6);
    const caps = applicableCaps(password, findings, lengthReport, chars);
    let capApplied = null;
    if (caps.length) {
      const tightest = caps.reduce((a, b) => (b.cap < a.cap ? b : a));
      if (score > tightest.cap) {
        capApplied = "Score capped at " + tightest.cap + " (" + tightest.rule + "): " + tightest.reason;
      }
      score = Math.min(score, tightest.cap);
    }
    score = Math.max(0, Math.min(100, pyRound(score)));
    const verdict = classify(score);

    return {
      score: score, raw_score: pyRound(rawPositive), classification: verdict.classification,
      summary: verdict.summary, band: verdict.band, cap_applied: capApplied, caps: caps,
      breakdown: {
        length: { earned: round1(lengthEarned), max: WEIGHTS.length,
                  detail: lengthReport.length + " characters (" + lengthReport.band + ")" },
        character_diversity: { earned: round1(diversityEarned), max: WEIGHTS.diversity,
                  detail: chars.character_type_count + " character types (" +
                          (chars.character_types.join(", ") || "none") + ")" },
        unique_character_ratio: { earned: round1(uniquenessEarned), max: WEIGHTS.uniqueness,
                  detail: Math.round(chars.unique_character_ratio * 100) + "% unique characters" },
        pattern_resistance: { earned: round1(patternEarned), max: WEIGHTS.pattern_resistance,
                  detail: distinct.length ? distinct.length + " distinct weakness categories detected"
                                          : "no predictable patterns detected" },
        not_a_common_password: { earned: notCommonEarned, max: WEIGHTS.not_common,
                  detail: (commonHit || breachHit) ? "common password or breach match"
                                                   : "not found in the common-password list" },
        unpredictability: { earned: round1(unpredictability), max: WEIGHTS.unpredictability,
                  detail: "bonus for length combined with variety and clear pattern scans" }
      },
      penalties: { total: penalty, by_category: penaltyBreakdown }
    };
  }

  function round1(n) { return pyRoundTo(n, 1); }

  // Round to `digits` decimals (half away from zero, like Python's round for
  // the values we produce) -- used to normalise floating-point noise.
  function roundTo(n, digits) {
    const factor = Math.pow(10, digits);
    return Math.round(n * factor) / factor;
  }

  function pyRoundTo(n, digits) {
    const factor = Math.pow(10, digits);
    return pyRound(n * factor) / factor;
  }

  // Python's round() uses round-half-to-even; Math.round() rounds half up.
  // Reproducing it here keeps the two engines bit-identical on boundary values
  // (for example a raw score of exactly 36.5).
  function pyRound(value) {
    const floor = Math.floor(value);
    const diff = value - floor;
    if (diff > 0.5) return floor + 1;
    if (diff < 0.5) return floor;
    return floor % 2 === 0 ? floor : floor + 1;
  }

  /* =====================================================================
   * 9. SUGGESTIONS
   * ===================================================================== */
  const ADVICE = {
    common_password: ["Stop using this password",
      "It appears in the bundled educational list of the most-used passwords, so it is inside " +
      "the first few thousand guesses of every attack tool.",
      "Create a brand-new password for this account and change it on any other account where " +
      "you reused it."],
    common_phrase: ["Do not use a famous phrase",
      "Quotations, lyrics and proverbs are collected in cracking wordlists, so a long but " +
      "well-known phrase is weaker than a short random one.",
      "Build a phrase from words that are unrelated to each other and meaningful only to you."],
    breach: ["Treat this password as compromised",
      "It matches an entry in the demo breach corpus. Real breach lists are built into " +
      "credential-stuffing tools and are tried automatically on login pages.",
      "Change it now, and enable MFA so a leaked password alone is not enough."],
    dictionary_word: ["Replace common words with unpredictable combinations",
      "Dictionary words -- even with capital letters or symbol swaps like '@' for 'a' -- are " +
      "enumerated early by cracking tools.",
      "Use a phrase of 4+ randomly chosen, unrelated words, or a password manager's random " +
      "generator."],
    sequence: ["Remove predictable sequences",
      "Runs such as 1234, abcd or their reverse shrink the search space dramatically: the " +
      "attacker guesses a pattern plus a start point, not every character.",
      "Break the run apart and mix in unrelated characters that do not follow each other on the " +
      "keyboard or in the alphabet."],
    keyboard_pattern: ["Avoid keyboard walks",
      "Shapes like qwerty, asdf, 1qaz or zxcv are in every wordlist, including reversed, " +
      "shifted and case-flipped versions.",
      "Pick characters that are not physically adjacent, or switch to a random generated password."],
    repeated_characters: ["Stop repeating the same character",
      "A long run of one character (aaaa, 1111) adds length but almost zero unpredictability.",
      "Keep the length, replace the repeated run with unrelated characters."],
    repeated_substring: ["Break up repeated blocks",
      "Repeating a block such as 'abcabc' or '121212' makes the password look longer without " +
      "making it harder to guess.",
      "Use a random generator, or choose a passphrase whose words do not repeat."],
    predictable_structure: ["Avoid word-plus-number shapes",
      "'word + 123' and 'word!2026' are two of the first patterns tools try, because they " +
      "satisfy composition rules while staying memorable.",
      "Prefer a longer passphrase or a fully random password. If you must remember it, make the " +
      "length do the work rather than the symbol."],
    year_pattern: ["Take the year out",
      "Birth years and the current year are the most attempted numeric suffixes, and they are " +
      "often discoverable from public profiles.",
      "Remove dates entirely, or bury them inside a long random string."],
    date_pattern: ["Remove date-shaped strings",
      "Birthdays and anniversaries are guessable from social media and public records.",
      "Pick unrelated characters that carry no personal meaning."],
    phone_pattern: ["Do not use a phone number",
      "Phone numbers are directly identifiable and appear in breach and marketing datasets.",
      "Use a random generated password instead."],
    personal_info: ["Remove your personal information",
      "Names, usernames and birth years can be collected from profiles, resumes, company pages " +
      "and breach dumps, then tried automatically.",
      "Avoid anything that identifies you; keep personal details out of passwords even when " +
      "they are easy to remember."],
    short_length: ["Increase the length",
      "Short passwords are guessed with brute force far more quickly than long ones.",
      "Aim for at least 12 characters, and 16+ for email, banking and work accounts."],
    low_variety: ["Add character variety",
      "Using only one character class keeps the search pool small.",
      "Mix upper and lower case, digits and symbols -- but rely on length and unpredictability first."]
  };

  const ALWAYS_USEFUL = [
    "Avoid reusing passwords across different accounts -- one breach would then expose every " +
    "account that shares the password.",
    "Use a password manager to generate and store unique passwords for every site.",
    "Enable MFA (app, hardware key or passkey) wherever it is offered; it protects you even if " +
    "the password leaks.",
    "Never share a password over email, chat or a phone call, and be sceptical of any page that " +
    "asks you to re-enter it after you clicked a link."
  ];

  function generateSuggestions(findings, lengthReport, chars, classification, includeHygiene) {
    const out = [], seen = new Set();
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const priorityMap = { critical: "high", high: "high", medium: "medium", low: "low", info: "low" };

    findings.slice().sort((a, b) => order[a.severity] - order[b.severity]).forEach((f) => {
      const advice = ADVICE[f.type];
      if (!advice || seen.has(advice[0])) return;
      seen.add(advice[0]);
      out.push({
        priority: priorityMap[f.severity] || "low", weakness: f.type, title: advice[0],
        risk: advice[1], action: advice[2], detected: f.description
      });
    });

    if (lengthReport && chars) {
      if (lengthReport.length < 12) {
        out.push({
          priority: "medium", weakness: "hygiene",
          title: "Consider using a longer password or a passphrase of 4+ unrelated words",
          risk: "Each extra character multiplies an attacker's work, and length is easier to " +
                "remember than a pile of symbols.",
          action: "Consider using a longer password or a passphrase of 4+ unrelated words " +
                  "(unique to you, generated by a password manager if possible).",
          detected: ""
        });
      }
      if (chars.character_type_count < 3) {
        out.push({
          priority: "medium", weakness: "hygiene",
          title: "Add another character type",
          risk: "Using one or two character classes keeps the pool an attacker must search small.",
          action: "Add another character type (upper case, digits or symbols) to widen the pool " +
                  "an attacker must search.", detected: ""
        });
      }
    }

    if ((classification === "VERY WEAK" || classification === "WEAK") &&
        !out.some((s) => s.weakness === "generator")) {
      out.push({
        priority: "high", weakness: "generator", title: "Let the tool generate one for you",
        risk: "Human-chosen passwords strongly favour memorable patterns, which is exactly what " +
              "attackers model.",
        action: "Use the built-in generator (Web Crypto / Python secrets) and save the result in " +
                "a password manager.",
        detected: ""
      });
    }

    if (includeHygiene !== false) {
      ALWAYS_USEFUL.forEach((line) => {
        out.push({
          priority: "low", weakness: "awareness",
          title: line.split("--")[0].split(";")[0].split(",")[0].trim().replace(/\.$/, ""),
          risk: "Password strength is only one part of account security.",
          action: line, detected: ""
        });
      });
    }
    return out;
  }

  /* =====================================================================
   * 10. MAIN ENTRY POINT
   * ===================================================================== */
  function analyzePassword(password, options) {
    const opts = options || {};
    const started = (typeof performance !== "undefined" && performance.now)
      ? performance.now() : Date.now();
    const text = typeof password === "string" ? password : "";
    const analysisId = "an_" + Math.random().toString(16).slice(2, 14);

    if (text.length > MAX_LENGTH) {
      return invalidResult(analysisId, "too_long",
        "Password exceeds the supported length (" + MAX_LENGTH + " characters). Long values are " +
        "rejected to protect the runtime, not because length hurts security.");
    }

    const lengthReport = analyzeLength(text);
    const chars = analyzeCharacters(text);
    const patternResult = detectAllPatterns(text, opts.context);
    const findings = patternResult.findings.slice();

    // Structural findings appended by the analyzer (mirrors Python).
    if (lengthReport.length > 0 && lengthReport.length < 12) {
      const shortFinding = finding("short_length", lengthReport.length < 8 ? "medium" : "low",
        "Short password",
        "Your password is " + lengthReport.length + " characters long. 12+ is the common modern " +
        "baseline, and 16+ is better for email, banking and work accounts.",
        "\u2022".repeat(lengthReport.length));
      shortFinding.penalty_bits = lengthReport.length < 8 ? 8.0 : 4.0;   // mirrors Python
      findings.push(shortFinding);
    }
    if (text && chars.character_type_count < 2) {
      const varietyFinding = finding("low_variety", "low", "Single character class",
        "Only one character class is used, which keeps the search pool small.",
        "\u2022".repeat(text.length));
      varietyFinding.penalty_bits = 3.0;                                  // mirrors Python
      findings.push(varietyFinding);
    }
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort((a, b) => (order[a.severity] - order[b.severity]) || (b.penalty_bits - a.penalty_bits));

    const penaltyBits = patternResult.pattern_penalty_bits;
    const entropy = entropyReport(text, penaltyBits);
    const structure = patternResult.structure;

    if (structure.is_passphrase_like) {
      const nonPhrase = findings.filter((f) => f.type !== "passphrase_structure");
      if (nonPhrase.length === 0) {
        entropy.effective_bits = round1(Math.min(entropy.passphrase_estimate_bits, entropy.effective_bits));
        entropy.effective_bits_source = "passphrase model (upper bound): " + structure.token_count +
          " words x ~12.6 bits per word, assuming random word selection";
        entropy.passphrase_model_caveat = "This assumes the words were chosen randomly and " +
          "independently. A human-chosen phrase of related or pretty words is much weaker than " +
          "this number suggests.";
      }
    }

    // Published-value correction. Wording is duplicated verbatim from
    // backend/services/password_analyzer.py so both runtimes explain the same
    // number in the same words: a character-space estimate is meaningless for a
    // string that already appears in a public list.
    if (findings.some((f) => f.type === "common_password" || f.type === "common_phrase" ||
                             f.type === "breach")) {
      entropy.effective_bits_source = "character-space upper bound -- NOT applicable here";
      entropy.known_value_caveat = "This value is in a public/common list, so the character-space " +
        "formula does not describe it. Its true cost to an attacker is a few thousand guesses at " +
        "most, no matter how long or complex the string looks.";
    }

    const scoring = scorePassword(text, findings);
    const guess = estimateGuessResistance(entropy.effective_bits);
    const suggestions = generateSuggestions(findings, lengthReport, chars,
                                            scoring.classification, opts.includeHygiene);
    const policy = checkPolicy(text, opts.policy, scoring.score, opts.context);
    const durationMs = ((typeof performance !== "undefined" && performance.now)
      ? performance.now() : Date.now()) - started;

    return {
      analysis_id: analysisId,
      engine: "javascript (browser, offline)",
      version: "1.0",
      analyzed_at: new Date().toISOString(),
      duration_ms: Math.round(durationMs * 100) / 100,
      score: scoring.score,
      classification: scoring.classification,
      classification_summary: scoring.summary,
      classification_band: scoring.band,
      score_cap_applied: scoring.cap_applied,
      findings: findings,
      suggestions: suggestions,
      metrics: {
        length: lengthReport.length,
        length_band: lengthReport.band,
        length_credit: lengthReport.credit,
        recommended_minimum_length: 12,
        is_recommended_length: lengthReport.is_recommended_length,
        character_type_count: chars.character_type_count,
        character_types: chars.character_types,
        unique_character_count: chars.unique_character_count,
        unique_character_ratio: chars.unique_character_ratio,
        has_lowercase: chars.has_lowercase, has_uppercase: chars.has_uppercase,
        has_digits: chars.has_digits, has_symbols: chars.has_symbols,
        has_spaces: chars.has_spaces, has_unicode: chars.has_unicode,
        is_common_password: findings.some((f) => f.type === "common_password"),
        in_demo_breach_corpus: findings.some((f) => f.type === "breach"),
        breach_prefix_checked: patternResult.breach_prefix,
        is_passphrase_like: structure.is_passphrase_like,
        token_count: structure.token_count,
        separators_used: structure.separators_used,
        pattern_count: findings.filter((f) => ["short_length", "low_variety",
          "passphrase_structure"].indexOf(f.type) === -1).length,
        weakness_count: findings.length,
        weakness_categories: patternResult.categories,
        has_sequence: findings.some((f) => f.type === "sequence"),
        has_keyboard_pattern: findings.some((f) => f.type === "keyboard_pattern"),
        has_repetition: findings.some((f) => ["repeated_characters", "repeated_substring"].indexOf(f.type) !== -1),
        has_dictionary_word: findings.some((f) => f.type === "dictionary_word"),
        has_personal_info: findings.some((f) => f.type === "personal_info"),
        has_predictable_structure: findings.some((f) => f.type === "predictable_structure"),
        has_year_pattern: findings.some((f) => f.type === "year_pattern")
      },
      length_analysis: lengthReport,
      character_analysis: chars,
      structure_analysis: structure,
      entropy: entropy,
      score_breakdown: {
        weights: WEIGHTS, penalty_caps: PENALTY_CAPS, raw_score: scoring.raw_score,
        components: scoring.breakdown, penalties: scoring.penalties,
        final_score: scoring.score, caps_evaluated: scoring.caps,
        rubric_note: "Project-defined rubric (length 35 + diversity 15 + uniqueness 10 + " +
          "pattern resistance 20 + not-common 10 + unpredictability 10, minus capped penalties). " +
          "These weights are not a universal security standard."
      },
      guess_resistance: guess,
      policy: policy,
      passphrase_guidance: {
        recommended_words: 4,
        bits_per_word_note: "4 randomly chosen words from a 6,000+ word list is roughly 50 bits; " +
                            "6 words is roughly 76 bits.",
        four_word_entropy_bits: round1(passphraseEntropyBits(4)),
        six_word_entropy_bits: round1(passphraseEntropyBits(6)),
        warning: "Never reuse a passphrase taken from a website, article, song lyric or this " +
                 "demo. Generate your own."
      },
      privacy: {
        password_stored: false, password_logged: false,
        password_returned_in_response: false, password_sent_to_external_service: false,
        context_stored: false, evidence_masked: true,
        network_calls_made: 0,
        note: "This analysis ran entirely in your browser. No request left the page, and nothing " +
              "was written to localStorage, sessionStorage, cookies or the console."
      },
      disclaimer: "Educational estimate only. Password strength cannot be perfectly determined " +
                  "by one formula: it depends on the attacker model, the hashing algorithm and " +
                  "work factor, rate limiting and whether the password is reused elsewhere."
    };
  }

  function invalidResult(analysisId, kind, reason) {
    return {
      analysis_id: analysisId, engine: "javascript (browser, offline)", version: "1.0",
      analyzed_at: new Date().toISOString(), duration_ms: 0,
      score: 0, classification: "VERY WEAK", classification_summary: "Nothing analyzed yet.",
      classification_band: "0-20", score_cap_applied: null,
      findings: [finding("input", "info", "Nothing to analyze", reason, "")],
      suggestions: [], metrics: { length: 0, pattern_count: 0, weakness_count: 0,
        character_type_count: 0, weakness_categories: {} },
      entropy: entropyReport("", 0), score_breakdown: { weights: WEIGHTS, components: {},
        penalties: { total: 0, by_category: {} }, final_score: 0 }, guess_resistance: {},
      policy: { policy_pass: false, checks: [], failures: [], failure_count: 1 },
      passphrase_guidance: {},
      privacy: { password_stored: false, password_logged: false, context_stored: false,
        password_sent_to_external_service: false, network_calls_made: 0 },
      disclaimer: "Educational estimate only.",
      input_error: { kind: kind, reason: reason }
    };
  }

  /* =====================================================================
   * 11. POLICY CHECKER
   * ===================================================================== */
  const PRESET_POLICIES = {
    nist_baseline: { name: "NIST-style baseline (length + blocklist, no composition rules)",
      minimum_length: 8, maximum_supported_length: 256, common_password_check: true,
      personal_info_check: true, require_uppercase: false, require_lowercase: false,
      require_digit: false, require_symbol: false, allow_spaces: true,
      min_unique_characters: 4, reject_breached: true, password_expiry_days: 0,
      minimum_strength_score: 0 },
    standard_account: { name: "Standard account (12+ characters)", minimum_length: 12,
      maximum_supported_length: 256, common_password_check: true, personal_info_check: true,
      require_uppercase: false, require_lowercase: false, require_digit: false,
      require_symbol: false, allow_spaces: true, min_unique_characters: 6,
      reject_breached: true, password_expiry_days: 0, minimum_strength_score: 0 },
    enterprise_iam: { name: "Enterprise IAM (16+ characters, strength enforced)",
      minimum_length: 16, maximum_supported_length: 256, common_password_check: true,
      personal_info_check: true, require_uppercase: false, require_lowercase: false,
      require_digit: false, require_symbol: false, allow_spaces: true,
      min_unique_characters: 8, reject_breached: true, password_expiry_days: 0,
      minimum_strength_score: 61 },
    legacy_bank: { name: "Legacy banking-style policy (shown as an anti-pattern)",
      minimum_length: 8, maximum_supported_length: 256, common_password_check: true,
      personal_info_check: true, require_uppercase: true, require_lowercase: true,
      require_digit: true, require_symbol: true, allow_spaces: true,
      min_unique_characters: 6, reject_breached: true, password_expiry_days: 90,
      minimum_strength_score: 0 },
    passphrase_friendly: { name: "Passphrase-friendly (16+ characters, spaces allowed)",
      minimum_length: 16, maximum_supported_length: 256, common_password_check: true,
      personal_info_check: true, require_uppercase: false, require_lowercase: false,
      require_digit: false, require_symbol: false, allow_spaces: true,
      min_unique_characters: 5, reject_breached: true, password_expiry_days: 0,
      minimum_strength_score: 0 }
  };

  function checkPolicy(password, policyOverride, strengthScore, context) {
    const policy = Object.assign({}, PRESET_POLICIES.standard_account, policyOverride || {});
    const text = password || "";
    const checks = [];
    const add = (id, label, passed, detail, required) => {
      checks.push({ id: id, label: label, passed: !!passed, detail: detail,
                    required: required !== false });
    };

    add("minimum_length", "At least " + policy.minimum_length + " characters",
        text.length >= policy.minimum_length, "length = " + text.length);
    add("maximum_length", "Not more than " + policy.maximum_supported_length + " characters",
        text.length <= policy.maximum_supported_length,
        "length = " + text.length + " (modern guidance: support 64+ and never truncate)");
    const unique = new Set(Array.from(text)).size;
    add("unique_characters", "At least " + policy.min_unique_characters + " unique characters",
        unique >= policy.min_unique_characters, "unique characters = " + unique);

    if (policy.common_password_check) {
      const common = COMMON_PASSWORDS.has(text.toLowerCase()) ||
                     COMMON_PASSWORDS.has(deleet(text).toLowerCase());
      add("common_password", "Not a known common password", !common,
          common ? "matched the educational common-password list"
                 : "not present in the common-password list");
    }
    if (policy.personal_info_check) {
      const hits = context ? detectPersonalInfo(text, context) : [];
      add("personal_info", "No personal information from the provided context", hits.length === 0,
          hits.length ? "overlap detected with supplied context"
                      : (context ? "no overlap detected" : "no context supplied (skipped)"),
          !!context);
    }
    [["require_uppercase", "Contains an uppercase letter", (s) => Array.from(s).some(isUpper)],
     ["require_lowercase", "Contains a lowercase letter", (s) => Array.from(s).some(isLower)],
     ["require_digit", "Contains a digit", (s) => Array.from(s).some(isDigit)],
     ["require_symbol", "Contains a symbol",
      (s) => Array.from(s).some((c) => COMMON_SYMBOLS.indexOf(c) !== -1)]
    ].forEach(([key, label, predicate]) => {
      if (policy[key]) add(key, label, predicate(text), "required by policy");
    });
    add("expiry", "Password rotation policy", true,
        policy.password_expiry_days
          ? "Forces rotation every " + policy.password_expiry_days + " days. Modern guidance: " +
            "rotate only on evidence of compromise, because forced rotation produces predictable " +
            "increments and weaker passwords."
          : "No forced periodic rotation. Rotate immediately if a breach or suspicion of " +
            "compromise occurs.", false);

    let strengthOk = true;
    if (policy.minimum_strength_score && strengthScore !== undefined) {
      strengthOk = strengthScore >= policy.minimum_strength_score;
      add("minimum_strength_score",
          "Strength score of at least " + policy.minimum_strength_score + "/100",
          strengthOk, "score = " + strengthScore + "/100");
    }

    const failures = checks.filter((c) => c.required && !c.passed);
    return {
      policy_name: policy.name, policy: policy, policy_pass: failures.length === 0,
      checks: checks, failures: failures, failure_count: failures.length,
      strength_score: strengthScore, strength_meets_policy: strengthOk,
      note: "Policy compliance and password strength are separate ideas. A policy says 'this is " +
            "allowed here'; strength says 'this is hard to guess'. Both are reported."
    };
  }

  /* =====================================================================
   * 12. SECURE GENERATOR (Web Crypto)
   * ===================================================================== */
  function randomInt(maxExclusive) {
    if (maxExclusive <= 0) return 0;
    const cryptoObj = (typeof crypto !== "undefined") ? crypto : null;
    if (cryptoObj && cryptoObj.getRandomValues) {
      // Rejection sampling removes modulo bias.
      const limit = Math.floor(0xFFFFFFFF / maxExclusive) * maxExclusive;
      const buf = new Uint32Array(1);
      let value;
      do { cryptoObj.getRandomValues(buf); value = buf[0]; } while (value >= limit);
      return value % maxExclusive;
    }
    // Fallback for very old browsers only; the UI warns when this path is used.
    return Math.floor(Math.random() * maxExclusive);
  }

  function generatePassword(options) {
    const o = Object.assign({
      length: 20, use_uppercase: true, use_lowercase: true, use_digits: true,
      use_symbols: true, avoid_ambiguous: true
    }, options || {});
    const AMBIGUOUS = "lI1O0o";
    const SYMBOL_SET = "!@#$%^&*()-_=+[]{}|;:,.<>?/~";
    const pools = [];
    const filter = (s) => o.avoid_ambiguous
      ? Array.from(s).filter((c) => AMBIGUOUS.indexOf(c) === -1).join("") : s;
    if (o.use_lowercase) pools.push(["lowercase", filter("abcdefghijklmnopqrstuvwxyz")]);
    if (o.use_uppercase) pools.push(["uppercase", filter("ABCDEFGHIJKLMNOPQRSTUVWXYZ")]);
    if (o.use_digits) pools.push(["digits", filter("0123456789")]);
    if (o.use_symbols) pools.push(["symbols", filter(SYMBOL_SET)]);
    if (!pools.length) throw new Error("At least one character class must be enabled.");

    const length = Math.max(8, Math.min(o.length | 0, 128));
    const alphabet = pools.map(([, chars]) => chars).join("");
    const characters = pools.map(([, chars]) => chars.charAt(randomInt(chars.length)));
    while (characters.length < length) characters.push(alphabet.charAt(randomInt(alphabet.length)));
    for (let i = characters.length - 1; i > 0; i--) {          // Fisher-Yates
      const j = randomInt(i + 1);
      const tmp = characters[i]; characters[i] = characters[j]; characters[j] = tmp;
    }
    const password = characters.join("");
    const bits = Math.round(length * Math.log2(alphabet.length) * 10) / 10;
    return {
      password: password, length: length, pool_size: alphabet.length, entropy_bits: bits,
      theoretical_entropy_bits: bits, classes_used: pools.map(([name]) => name),
      generator: "Web Crypto getRandomValues (CSPRNG, browser)",
      note: "Generated locally in memory using the browser's cryptographic random source. " +
            "Nothing is stored, logged or transmitted."
    };
  }

  function generatePassphrase(options) {
    const o = Object.assign({ words: 5, separator: "-", capitalise: false,
                              append_number: false }, options || {});
    const vocabulary = PASSPHRASE_WORDS.map((w) => w.toLowerCase());
    const words = Math.max(3, Math.min(o.words | 0, 10));
    const chosen = [];
    for (let i = 0; i < words; i++) {
      let word = vocabulary[randomInt(vocabulary.length)];
      chosen.push(o.capitalise ? word.charAt(0).toUpperCase() + word.slice(1) : word);
    }
    if (o.append_number) chosen.push(String(randomInt(100)));
    const phrase = chosen.join(o.separator);
    const bits = Math.round((words * Math.log2(vocabulary.length) +
      (o.append_number ? Math.log2(100) : 0)) * 10) / 10;
    return {
      password: phrase, passphrase: phrase, length: phrase.length, word_count: words,
      wordlist_size: vocabulary.length,
      bits_per_word: Math.round(Math.log2(vocabulary.length) * 100) / 100,
      entropy_bits: bits, theoretical_entropy_bits: bits, separator: o.separator,
      generator: "Web Crypto getRandomValues + local word list",
      note: "DEMO EXAMPLE -- generate your own and store it in a password manager."
    };
  }

  /* =====================================================================
   * EXPORTS
   * ===================================================================== */
  return {
    analyzePassword: analyzePassword,
    analyzeLength: analyzeLength,
    analyzeCharacters: analyzeCharacters,
    analyzeStructure: analyzeStructure,
    detectAllPatterns: detectAllPatterns,
    detectSequences: detectSequences,
    detectRepetition: detectRepetition,
    detectKeyboardPatterns: detectKeyboardPatterns,
    detectDictionaryWords: detectDictionaryWords,
    detectPredictableStructure: detectPredictableStructure,
    detectPersonalInfo: detectPersonalInfo,
    detectCommonPassword: detectCommonPassword,
    detectCommonPhrases: detectCommonPhrases,
    detectBreach: detectBreach,
    isCommonPassword: (pw) => COMMON_PASSWORDS.has(String(pw || "").toLowerCase()),
    scorePassword: scorePassword,
    classify: classify,
    entropyReport: entropyReport,
    estimateGuessResistance: estimateGuessResistance,
    generateSuggestions: generateSuggestions,
    checkPolicy: checkPolicy,
    presetPolicies: PRESET_POLICIES,
    generatePassword: generatePassword,
    generatePassphrase: generatePassphrase,
    sha1Hex: sha1Hex,
    passphraseEntropyBits: passphraseEntropyBits,
    dataStats: {
      common_passwords: COMMON_PASSWORDS.size,
      keyboard_patterns: KEYBOARD_PATTERNS.length,
      common_phrases: COMMON_PHRASES.size,
      passphrase_words: PASSPHRASE_WORDS.length
    }
  };
});
