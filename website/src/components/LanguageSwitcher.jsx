import { GlobeHemisphereWest } from "@phosphor-icons/react";
import { localeOptions, setLocale, t, useLocale } from "../i18n";

export function LanguageSwitcher({ compact = false }) {
  const locale = useLocale();
  return (
    <label className={`language-switcher${compact ? " language-switcher--compact" : ""}`} title={t("语言")} data-i18n-ignore>
      <GlobeHemisphereWest aria-hidden="true" />
      <select aria-label={t("语言")} value={locale} onChange={(event) => setLocale(event.target.value)}>
        {localeOptions.map((option) => <option value={option.code} key={option.code}>{compact ? option.short : option.label}</option>)}
      </select>
    </label>
  );
}
