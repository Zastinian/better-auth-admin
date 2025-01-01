import { defineConfig } from "tsup";

export default defineConfig(({ watch = false }) => ({
  clean: true,
  dts: true,
  entry: {
    index: "src/index.ts",
    client: "src/client.ts",
  },
  format: "esm",
  splitting: false,
  watch,
  minify: !watch,
}));
