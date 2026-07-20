import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import generatedMessages from "./src/i18n/messages.generated.js";

const localeModulePrefix = "virtual:trustdb-messages/";
const resolvedLocaleModulePrefix = `\0${localeModulePrefix}`;

const localeMessagesPlugin = {
  name: "trustdb-locale-messages",
  resolveId(id) {
    if (id.startsWith(localeModulePrefix)) return `\0${id}`;
    return null;
  },
  load(id) {
    if (!id.startsWith(resolvedLocaleModulePrefix)) return null;
    const locale = id.slice(resolvedLocaleModulePrefix.length);
    const messages = generatedMessages[locale];
    if (!messages) throw new Error(`unknown TrustDB locale: ${locale}`);
    return `export default ${JSON.stringify(messages)};`;
  },
};

export default defineConfig({
  optimizeDeps: {
    include: ["react", "react-dom/client"],
  },
  server: {
    host: "0.0.0.0",
    allowedHosts: ["terminal.local", "localhost", "127.0.0.1"],
    warmup: {
      clientFiles: ["./src/main.jsx"],
    },
  },
  plugins: [localeMessagesPlugin, react()],
});
