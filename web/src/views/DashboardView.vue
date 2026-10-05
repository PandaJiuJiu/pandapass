<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, ApiError, type Project } from '@/api/client'

const router = useRouter()
const projects = ref<Project[]>([])
const loading = ref(true)
const error = ref('')

const creating = ref(false)
const name = ref('')
const slug = ref('')
const description = ref('')

/** Derive a slug from the name unless the user has typed their own. */
let slugTouched = false
function onNameInput(): void {
  if (slugTouched) return
  slug.value = name.value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    projects.value = await api.listProjects()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : 'Could not load projects'
  } finally {
    loading.value = false
  }
}

async function create(): Promise<void> {
  if (!name.value || !slug.value) return
  creating.value = true
  error.value = ''
  try {
    await api.createProject(name.value, slug.value, description.value || undefined)
    name.value = ''
    slug.value = ''
    description.value = ''
    slugTouched = false
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : 'Could not create project'
  } finally {
    creating.value = false
  }
}

onMounted(refresh)
</script>

<template>
  <div>
    <h1 style="font-size: 20px; margin-top: 0">Projects</h1>
    <p v-if="error" class="error">{{ error }}</p>
    <p v-if="loading" class="dim">Loading…</p>

    <div v-else class="card" style="padding: 0">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th style="width: 20%">Slug</th>
            <th style="width: 16%">Your role</th>
            <th style="width: 10%" />
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="p in projects"
            :key="p.id"
            style="cursor: pointer"
            @click="router.push(`/projects/${p.slug}`)"
          >
            <td>
              {{ p.name }}
              <div v-if="p.description" class="dim" style="font-size: 12px">
                {{ p.description }}
              </div>
            </td>
            <td class="mono dim">{{ p.slug }}</td>
            <td class="dim">{{ p.user_role ?? '—' }}</td>
            <td @click.stop>
              <button @click="router.push(`/projects/${p.slug}`)">Open</button>
            </td>
          </tr>
          <tr v-if="!projects.length">
            <td colspan="4" class="dim">No projects yet. Create one below.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <strong style="font-size: 14px">New project</strong>
      <div style="margin-top: 12px">
        <label>
          Name
          <input v-model="name" placeholder="My App" @input="onNameInput" />
        </label>
        <div class="row">
          <label style="flex: 1">
            Slug
            <input
              v-model="slug"
              class="mono"
              placeholder="my-app"
              @input="slugTouched = true"
            />
          </label>
          <label style="flex: 2">
            Description <span class="dim">(optional)</span>
            <input v-model="description" />
          </label>
        </div>
        <button class="primary" :disabled="creating || !name || !slug" @click="create">
          {{ creating ? 'Creating…' : 'Create' }}
        </button>
      </div>
    </div>
  </div>
</template>
