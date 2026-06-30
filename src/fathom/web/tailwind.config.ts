import type { Config } from "tailwindcss";

// Design tokens for the dashboard/explorer shell (frontend ADD §8). Charts are themed
// through the single ChartAdapter palette so ECharts shares these colours.
const config: Config = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // The shared chart/UI palette (kept in sync with charts/ChartAdapter palette).
        fathom: {
          bg: "#0f1116",
          panel: "#171a21",
          accent: "#4f9cff",
          warn: "#e0a458",
          danger: "#e06c75",
        },
        // Fathomline brand — Depth Scale palette. Values come from the CSS variables defined in
        // src/index.css (mirrored from the canonical assets/brand/brand-tokens.css), so the hex
        // lives in one place. Use e.g. `text-sounding-blue`, `bg-abyss-navy`.
        "abyss-navy": "var(--abyss-navy)",
        "trench-black": "var(--trench-black)",
        "abyssal-blue": "var(--abyssal-blue)",
        "sounding-blue": "var(--sounding-blue)",
        "sounding-teal": "var(--sounding-teal)",
        "shoal-teal": "var(--shoal-teal)",
        "plummet-amber": "var(--plummet-amber)",
        steel: "var(--steel)",
      },
      fontFamily: {
        heading: "var(--font-heading)",
        body: "var(--font-body)",
        mono: "var(--font-mono)",
      },
    },
  },
  plugins: [],
};

export default config;
