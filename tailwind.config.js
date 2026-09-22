/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
    "./UI/**/*.{js,ts,jsx,tsx,html}"
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      colors: {
        cyber: {
          bg: '#090D16',
          card: '#111827',
          panel: '#0d1322',
          subtle: '#0f172a',
          border: '#1e293b',
          borderFocus: '#334155',
          cyan: '#06b6d4',
          neonRed: '#ef4444',
          amber: '#f59e0b',
          emerald: '#10b981'
        }
      }
    },
  },
  plugins: [],
};
