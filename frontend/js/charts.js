/**
 * frontend/js/charts.js
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   Tiny, dependency-free SVG chart builders for the dashboard.
 *
 * WHY HAND-WRITTEN SVG INSTEAD OF CHART.JS
 *   * The brief lists Chart.js as an option, but this project must work with
 *     zero network access (GitHub Pages, an offline demo laptop, or an iframe
 *     preview with no external requests). A 3 kB of SVG code beats a CDN
 *     dependency that silently fails offline.
 *   * Every figure is built from data that contains no secret material:
 *     counts, buckets and percentages only.
 *
 * ACCESSIBILITY
 *   Each chart returns an <svg> with role="img" plus a text summary that a
 *   screen reader can read, and a legend below the figure. Colour is never the
 *   only differentiator: labels and values are printed next to every bar.
 * ---------------------------------------------------------------------------
 */
(function (root) {
  "use strict";

  const PALETTE = {
    "VERY WEAK": "#ff4d5e",
    "WEAK": "#ff9147",
    "MODERATE": "#ffd23f",
    "STRONG": "#4cd97b",
    "VERY STRONG": "#2ee6a8"
  };

  const ESC = (text) => String(text).replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  /* ---------------------------------------------------------------- helpers */
  function emptyChart(message) {
    return `<p class="text-faint small mb-0">${ESC(message)}</p>`;
  }

  /* ------------------------------------------------- 1. Vertical bar chart */
  /**
   * items: [{ label, value, color }]
   * Used for the strength distribution (5 bands).
   */
  function verticalBars(items, options) {
    const opts = Object.assign({ height: 170, maxOverride: 0, valueSuffix: "" }, options || {});
    if (!items.length) return emptyChart("No data yet.");
    const max = opts.maxOverride || Math.max.apply(null, items.map((i) => i.value)) || 1;
    const width = 100 / items.length;
    const summary = items.map((i) => `${i.label}: ${i.value}`).join(", ");

    let bars = "";
    items.forEach((item, index) => {
      const available = opts.height - 52;
      const height = max ? Math.max((item.value / max) * available, item.value > 0 ? 3 : 0) : 0;
      const x = index * width + width * 0.16;
      const barWidth = width * 0.68;
      const y = 30 + (available - height);
      // Labels may contain "\n" to force a second line ("VERY\nWEAK"), which
      // keeps long band names readable without rotating them or overflowing.
      const labelLines = String(item.label).split("\n").slice(0, 2);
      const labelSvg = labelLines.map((line, lineIndex) => `
        <text x="${(x + barWidth / 2).toFixed(1)}" y="${(opts.height - 30 + lineIndex * 11).toFixed(1)}"
              text-anchor="middle" font-size="9.5" fill="#a9b6d4">${ESC(line)}</text>`).join("");
      bars += `
        <text x="${(x + barWidth / 2).toFixed(1)}" y="${(y - 7).toFixed(1)}" text-anchor="middle"
              font-size="11" font-weight="700" fill="#e9eefb">${item.value}${ESC(opts.valueSuffix)}</text>
        <rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barWidth.toFixed(1)}" height="${height.toFixed(1)}"
              rx="6" fill="${item.color}" opacity="0.92"></rect>${labelSvg}`;
    });

    return `<svg class="chart-svg" viewBox="0 0 320 ${opts.height}" role="img"
                aria-label="Bar chart. ${ESC(summary)}">${bars}</svg>`;
  }

  /* ------------------------------------------------ 2. Horizontal bar list */
  /**
   * items: [{ label, value, color? }]
   * Used for weakness frequency and pattern frequency.
   */
  function horizontalBars(items, options) {
    const opts = Object.assign({ maxItems: 8, valueSuffix: "" }, options || {});
    if (!items.length) return emptyChart("No data yet.");
    const trimmed = items.slice(0, opts.maxItems);
    const max = Math.max.apply(null, trimmed.map((i) => i.value)) || 1;

    const rows = trimmed.map((item) => {
      const percent = Math.max((item.value / max) * 100, 2);
      const color = item.color || "#4cc9f0";
      return `
        <div class="bar-row" style="grid-template-columns:150px 1fr 46px">
          <span class="small" style="color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                title="${ESC(item.label.replace(/_/g, " "))}">${ESC(item.label.replace(/_/g, " "))}</span>
          <span class="bar-track"><span class="bar-fill" style="width:${percent.toFixed(1)}%;background:${color}"></span></span>
          <span class="bar-value">${item.value}${ESC(opts.valueSuffix)}</span>
        </div>`;
    }).join("");

    const summary = trimmed.map((i) => `${i.label.replace(/_/g, " ")}: ${i.value}`).join(", ");
    return `<div role="img" aria-label="Bar chart. ${ESC(summary)}">${rows}</div>`;
  }

  /* -------------------------------------------------- 3. Score histogram */
  function histogram(buckets) {
    if (!buckets.length) return emptyChart("No data yet.");
    const height = 150;
    const max = Math.max.apply(null, buckets.map((b) => b.count)) || 1;
    const width = 100 / buckets.length;

    let bars = "";
    buckets.forEach((bucket, index) => {
      const available = height - 44;
      const barHeight = Math.max((bucket.count / max) * available, bucket.count > 0 ? 3 : 0);
      const x = index * width + width * 0.18;
      const barWidth = width * 0.64;
      const y = 26 + (available - barHeight);
      const bucketStart = parseInt(bucket.bucket.split("-")[0], 10);
      const color = bucketStart >= 81 ? PALETTE["VERY STRONG"]
        : bucketStart >= 61 ? PALETTE.STRONG
        : bucketStart >= 41 ? PALETTE.MODERATE
        : bucketStart >= 21 ? PALETTE.WEAK : PALETTE["VERY WEAK"];
      bars += `
        <text x="${(x + barWidth / 2).toFixed(1)}" y="${(y - 6).toFixed(1)}" text-anchor="middle"
              font-size="10" font-weight="700" fill="#e9eefb">${bucket.count}</text>
        <rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barWidth.toFixed(1)}" height="${barHeight.toFixed(1)}"
              rx="4" fill="${color}" opacity="0.9"></rect>
        <text x="${(x + barWidth / 2).toFixed(1)}" y="${height - 22}" text-anchor="middle"
              font-size="8.5" fill="#a9b6d4" transform="rotate(-40 ${(x + barWidth / 2).toFixed(1)} ${height - 22})"
        >${ESC(bucket.bucket)}</text>`;
    });

    const summary = buckets.map((b) => `${b.bucket}: ${b.count}`).join(", ");
    return `<svg class="chart-svg" viewBox="0 0 320 ${height}" role="img"
                aria-label="Histogram of scores. ${ESC(summary)}">${bars}</svg>`;
  }

  /* ------------------------------------------------------- 4. Donut gauge */
  function scoreGauge(score, color) {
    const radius = 46;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference * (1 - Math.max(0, Math.min(100, score)) / 100);
    return `
      <svg class="chart-svg" viewBox="0 0 120 120" role="img"
           aria-label="Overall score ${score} out of 100" style="max-width:190px;margin:0 auto">
        <circle cx="60" cy="60" r="${radius}" fill="none" stroke="rgba(126,158,214,0.16)" stroke-width="11"></circle>
        <circle cx="60" cy="60" r="${radius}" fill="none" stroke="${color}" stroke-width="11"
                stroke-linecap="round" stroke-dasharray="${circumference.toFixed(1)}"
                stroke-dashoffset="${offset.toFixed(1)}" transform="rotate(-90 60 60)"></circle>
        <text x="60" y="58" text-anchor="middle" font-size="27" font-weight="700" fill="#e9eefb">${score}</text>
        <text x="60" y="76" text-anchor="middle" font-size="10" fill="#a9b6d4">out of 100</text>
      </svg>`;
  }

  root.PSACharts = {
    verticalBars: verticalBars,
    horizontalBars: horizontalBars,
    histogram: histogram,
    scoreGauge: scoreGauge,
    palette: PALETTE
  };
})(typeof self !== "undefined" ? self : this);
