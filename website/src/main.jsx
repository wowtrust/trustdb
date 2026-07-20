import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.jsx";
import { initializeLocaleMessages, installDomTranslations } from "./i18n";
import "./styles.css";

async function bootstrap() {
  await initializeLocaleMessages();
  createRoot(document.getElementById("root")).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );

  installDomTranslations();
}

void bootstrap();
