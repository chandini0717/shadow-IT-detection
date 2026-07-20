/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        display: ["'Segoe UI'", "system-ui", "sans-serif"],
        sans: ["system-ui", "'Segoe UI'", "sans-serif"],
        mono: ["'Cascadia Code'", "'SFMono-Regular'", "Consolas", "ui-monospace", "monospace"],
      },
      colors: {
        base: {
          950: "#070B14",
          900: "#0B111F",
          800: "#111A2E",
          700: "#1A2540",
          600: "#26365A",
        },
        signal: {
          cyan: "#2DD4E8",
          amber: "#F5A524",
          red: "#F5455C",
          green: "#34D399",
        },
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(45,212,232,0.15), 0 8px 30px rgba(0,0,0,0.35)",
      },
      keyframes: {
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
        pulseRing: {
          "0%": { transform: "scale(0.8)", opacity: "0.8" },
          "100%": { transform: "scale(2.2)", opacity: "0" },
        },
      },
      animation: {
        scan: "scan 2.2s linear infinite",
        pulseRing: "pulseRing 1.8s ease-out infinite",
      },
    },
  },
  plugins: [],
};
