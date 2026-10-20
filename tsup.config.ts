import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node18",
  clean: true,
  minify: false,
  sourcemap: true,
  // Keep the shebang so the published bin is directly executable.
  banner: { js: "#!/usr/bin/env node" },
});
