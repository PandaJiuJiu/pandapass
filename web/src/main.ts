import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import { router } from './router'
import { i18n, setLocale, type SupportedLocale } from './i18n'
import './style.css'

const app = createApp(App)

app.use(createPinia())
app.use(router)
app.use(i18n)

// Keep <html lang> in sync with the active locale for a11y and i18n.
const composer = i18n.global as unknown as { locale: { value: string } }
setLocale(composer.locale.value as SupportedLocale)

app.mount('#app')