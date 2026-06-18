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
      },
    },
  },
  plugins: [],
};

export default config;
