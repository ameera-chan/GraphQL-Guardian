import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { DEFAULT_TARGET_ENDPOINT, getApiErrorMessage, scanAPI } from '../utils/api'

function ScanForm() {
  const navigate = useNavigate()
  const [formData, setFormData] = useState({
    endpoint: DEFAULT_TARGET_ENDPOINT,
    profile: 'default',
    technique: 'IDAC',
    enableMl: false,
    enableLlm: false,
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [endpointError, setEndpointError] = useState('')

  const updateField = (field, value) => {
    setFormData((current) => ({ ...current, [field]: value }))
    if (field === 'endpoint') setEndpointError('')
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    try {
      new URL(formData.endpoint)
    } catch {
      setEndpointError('Enter a valid URL.')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const result = await scanAPI.createScan(formData)
      navigate(`/results/${result.scan_id}`)
    } catch (err) {
      setError(getApiErrorMessage(err, 'Failed to create scan'))
      setLoading(false)
    }
  }

  return (
    <section className="scan-page" aria-label="Configure GraphQL scan">
      <div className="scan-header-block">
        <div>
          <h1>New Scan</h1>
        </div>
      </div>

      {error && (
        <div className="dashboard-alert" role="status">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="scan-layout">
        <div className="scan-panel">
          <div className="scan-panel-header">
            <h2>Target</h2>
          </div>

          <div className="scan-form-body">
            <div className="scan-field scan-field-full">
              <label htmlFor="endpoint">Endpoint URL</label>
              <input
                id="endpoint"
                type="url"
                value={formData.endpoint}
                onChange={(e) => updateField('endpoint', e.target.value)}
                placeholder={DEFAULT_TARGET_ENDPOINT}
                aria-invalid={Boolean(endpointError)}
                aria-describedby={endpointError ? 'endpoint-error' : undefined}
                required
              />
              {endpointError && (
                <small id="endpoint-error" className="scan-field-error">
                  {endpointError}
                </small>
              )}
            </div>

            <div className="scan-field">
              <label htmlFor="profile">Profile</label>
              <select
                id="profile"
                value={formData.profile}
                onChange={(e) => updateField('profile', e.target.value)}
              >
                <option value="passive">Passive</option>
                <option value="default">Default</option>
                <option value="aggressive">Aggressive</option>
              </select>
            </div>

            <div className="scan-field">
              <label htmlFor="technique">Checks</label>
              <select
                id="technique"
                value={formData.technique}
                onChange={(e) => updateField('technique', e.target.value)}
              >
                <option value="IDAC">All</option>
                <option value="A">Auth</option>
                <option value="I">Injection</option>
                <option value="D">DoS</option>
                <option value="AI">Auth + injection</option>
              </select>
            </div>

            <fieldset className="scan-options scan-field-full">
              <legend>Analysis</legend>
              <label className="scan-check" htmlFor="enableMl">
                <input
                  id="enableMl"
                  type="checkbox"
                  checked={formData.enableMl}
                  onChange={(e) => updateField('enableMl', e.target.checked)}
                />
                <span>ML analysis</span>
              </label>
              <label className="scan-check" htmlFor="enableLlm">
                <input
                  id="enableLlm"
                  type="checkbox"
                  checked={formData.enableLlm}
                  onChange={(e) => updateField('enableLlm', e.target.checked)}
                />
                <span>AI review</span>
              </label>
            </fieldset>

            <div className="scan-actions scan-field-full">
              <button type="submit" disabled={loading} className="scan-submit">
                {loading ? 'Starting...' : 'Start Scan'}
              </button>
            </div>
          </div>
        </div>
      </form>
    </section>
  )
}

export default ScanForm
