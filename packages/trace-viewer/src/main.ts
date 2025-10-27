import { Classic } from "@caido/primevue";
import PrimeVue from "primevue/config";
import { createApp } from "vue";

import App from "./App.vue";
import "./styles/index.css";

const app = createApp(App);

app.use(PrimeVue, {
  unstyled: true,
  pt: Classic,
});

app.mount("#app");
