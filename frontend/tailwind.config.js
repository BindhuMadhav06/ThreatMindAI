/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#020617',
          card: '#0f172a',
          accent: '#06b6d4',
          highlight: '#3b82f6'
        }
      }
    },
  },
  plugins: [],
}
