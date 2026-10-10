import { createI18n } from 'vue-i18n'
import en from './en'
import zhCN from './zh-CN'

export type MessageSchema = typeof en

export type SupportedLocale = 'en' | 'zh-CN'

function detectLocale(): SupportedLocale {
  try {
    const saved = localStorage.getItem('pandapass.locale')
    if (saved === 'en' || saved === 'zh-CN') return saved
  } catch {
    // Private mode / disabled storage — fall through to language detection.
  }
  return navigator.language.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en'
}

export const i18n = createI18n({
  legacy: false,
  locale: detectLocale(),
  fallbackLocale: 'en',
  messages: { en, 'zh-CN': zhCN },
})

export function setLocale(locale: SupportedLocale): void {
  // `global` is typed via the untyped createI18n overload; cast to the
  // minimal composer shape we need.
  const composer = i18n.global as unknown as { locale: { value: string } }
  composer.locale.value = locale
  try {
    localStorage.setItem('pandapass.locale', locale)
  } catch {
    // Non-fatal: locale just won't persist.
  }
  document.documentElement.lang = locale
}