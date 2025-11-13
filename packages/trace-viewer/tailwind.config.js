import tailwindPrimeui from "tailwindcss-primeui";
import tailwindcssCaido from "@caido/tailwindcss";

export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts}",
    "./node_modules/@caido/primevue/dist/primevue.mjs",
  ],
  darkMode: ["selector", '[data-mode="dark"]'],
  plugins: [tailwindPrimeui, tailwindcssCaido],
}
