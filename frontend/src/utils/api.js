import axios from 'axios'

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api'
export const DEFAULT_TARGET_ENDPOINT =
  import.meta.env.VITE_DEFAULT_TARGET_ENDPOINT || 'http://localhost:5013/graphql'

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 8000,
  headers: {
    'Content-Type': 'application/json',
  },
})

export function getApiErrorMessage(err, fallback = 'Request failed') {
  const detail = err?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail
      .map((item) => item?.msg || item?.message || JSON.stringify(item))
      .join('; ')
  }
  if (detail && typeof detail === 'object') {
    return detail.message || JSON.stringify(detail)
  }
  return err?.message || fallback
}

export const scanAPI = {
  // Create a new scan
  createScan: async ({
    endpoint,
    riskLevel = 1,
    technique = 'IDAC',
    profile = 'default',
    enableMl = false,
    enableLlm = false,
  }) => {
    const response = await api.post('/scan', {
      endpoint,
      risk_level: riskLevel,
      technique,
      profile,
      enable_ml: enableMl,
      enable_llm: enableLlm,
    })
    return response.data
  },

  // Get scan status
  getStatus: async (scanId) => {
    const response = await api.get(`/scan/${scanId}/status`)
    return response.data
  },

  // Get scan report
  getReport: async (scanId) => {
    const response = await api.get(`/scan/${scanId}/report`)
    return response.data
  },

  // Get graph data
  getGraph: async (scanId) => {
    const response = await api.get(`/scan/${scanId}/graph`)
    return response.data
  },

  // List all scans
  listScans: async (limit = 10, offset = 0) => {
    const response = await api.get('/scans', {
      params: { limit, offset },
    })
    return response.data
  },

  // Delete a scan
  deleteScan: async (scanId) => {
    const response = await api.delete(`/scan/${scanId}`)
    return response.data
  },

  // Get statistics
  getStats: async () => {
    const response = await api.get('/stats')
    return response.data
  },
}

export default api
