import type { RawConfigurationOrFn } from "knip/dist/types/config.js";

const config: RawConfigurationOrFn = {
  workspaces: {
    ".": {
      entry: ["caido.config.ts", "eslint.config.mjs"],
      ignoreDependencies: ["@caido/sdk-backend", "rollup-plugin-dts"],
    },
    "packages/backend": {
      entry: ["src/index.ts"],
      project: ["src/**/*.ts"],
      ignoreDependencies: ["caido", "@lezer/common", "@lezer/generator"],
      ignore: [
        "src/parsers/**/__generated__*",
        "src/checks/sql-injection/mysql-time-based/**",
      ],
    },
    "packages/frontend": {
      entry: ["src/index.ts"],
      project: ["src/**/*.{ts,tsx,vue}"],
      ignore: [
        "src/views/Queue.vue",
        "src/components/queue/**",
        "src/types/queue.ts",
      ],
    },
    "packages/shared": {
      entry: ["src/index.ts"],
      project: ["src/**/*.ts"],
    },
    "packages/engine": {
      entry: ["src/index.ts"],
      project: ["src/**/*.ts"],
      ignoreDependencies: ["caido"],
      ignore: ["src/__tests__/**"],
    },
    "packages/trace-viewer": {
      entry: ["src/main.ts"],
      project: ["src/**/*.{ts,vue}"],
      ignoreDependencies: ["postcss", "@fortawesome/fontawesome-free"],
    },
  },
};

export default config;
