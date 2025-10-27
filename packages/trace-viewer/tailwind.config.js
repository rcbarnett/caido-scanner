import tailwindPrimeui from "tailwindcss-primeui";

export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts}",
    "./node_modules/@caido/primevue/dist/primevue.mjs",
  ],
  theme: {
    extend: {},
  },
  darkMode: ["selector", '[data-mode="dark"]'],
  plugins: [tailwindPrimeui],
}
