<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { api, ApiError, type Environment } from '@/api/client'
import SecretTable from '@/components/SecretTable.vue'

const props = defineProps<{ slug: string }>()

const envs = ref<Environment[]>([])
const selected = ref('')
const loading = ref(true)
const error = ref('')

const envName = ref('')
const envSlug = ref('')
const creating = ref(false)

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    envs.value = await api.listEnvs(props.slug)
    // Keep the current selection if it still exists, otherwise fall back to the
    // first environment so the page is never in a state showing nothing.
    if (!envs.value.some((e) => e.slug === selected.value)) {
      selected.value = envs.value[0]?.slug ?? ''
    }
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : 'Could not load environments'
  } finally {
    loading.value = false
  }
}

async function createEnv(): Promise<void> {
  if (!envName.value || !envSlug.value) return
  creating.value = true
  error.value = ''
  try {
    await api.createEnv(props.slug, envName.value, envSlug.value)
    envName.value = ''
    envSlug.value = ''
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : 'Could not create environment'
  } finally {
    creating.value = false
  }
}

// The slug is a route param, so navigating between projects changes it in place
// rather than remounting the view.
watch(() => props.slug, refresh)

onMounted(refresh)
</script>

<template>
  <div>
    <div class="spread" style="margin-bottom: 16px">
      <h1 style="font-size: 20px; margin: 0">
        {{ slug }} <span v-if="selected" class="dim">/ {{ selected }}</span>
      </h1>
      <router-link to="/projects" class="dim" style="font-size: 13px">← All projects</router-link>
    </div>

    <p v-if="error" class="error">{{ error }}</p>
    <p v-if="loading" class="dim">Loading…</p>

    <template v-else>
      <div class="row" style="margin-bottom: 16px; flex-wrap: wrap">
        <button
          v-for="e in envs"
          :key="e.id"
          :class="{ primary: e.slug === selected }"
          @click="selected = e.slug"
        >
          {{ e.name }}
        </button>
        <span v-if="!envs.length" class="dim">No environments yet.</span>
      </div>

      <div class="card">
        <SecretTable v-if="selected" :project="slug" :env="selected" />
        <p v-else class="dim">Create an environment to start storing secrets.</p>
      </div>

      <div class="card" style="background: var(--surface-2)">
        <strong style="font-size: 14px">New environment</strong>
        <div class="row" style="margin-top: 10px">
          <input v-model="envName" placeholder="Production" style="flex: 1" />
          <input v-model="envSlug" placeholder="prod" class="mono" style="flex: 0 0 30%" />
          <button class="primary" :disabled="creating || !envName || !envSlug" @click="createEnv">
            Add
          </button>
        </div>
      </div>
    </template>
  </div>
</template>
