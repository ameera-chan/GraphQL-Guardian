import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getApiErrorMessage, scanAPI } from '../utils/api'

function Dashboard() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let mounted = true

    async function loadDashboard() {
      try {
        const statsData = await scanAPI.getStats()
        if (!mounted) return
        setStats(statsData)
      } catch (err) {
        if (!mounted) return
        setError(getApiErrorMessage(err, 'API is not reachable'))
      } finally {
        if (mounted) setLoading(false)
      }
    }

    loadDashboard()
    return () => {
      mounted = false
    }
  }, [])

  const findings = stats?.total_findings || {}
  const statusCounts = stats?.by_status || {}
  const totalFindings =
    (findings.critical || 0) +
    (findings.high || 0) +
    (findings.medium || 0) +
    (findings.low || 0) +
    (findings.info || 0)

  return (
    <section className="dashboard-page" aria-label="GuardQL dashboard">
      <div className="dashboard-header-block">
        <div>
          <h1>Dashboard</h1>
        </div>
        <Link className="dashboard-primary-action" to="/scans">
          New Scan
        </Link>
      </div>

      {error && (
        <div className="dashboard-alert" role="status">
          {error}. Run <span>guardql web</span> and refresh.
        </div>
      )}

      <div className="dashboard-metrics" aria-busy={loading}>
        <div className="dashboard-metric">
          <span>Total Scans</span>
          <strong>{loading ? '-' : stats?.total_scans || 0}</strong>
        </div>
        <div className="dashboard-metric">
          <span>Completed</span>
          <strong>{loading ? '-' : statusCounts.completed || 0}</strong>
        </div>
        <div className="dashboard-metric">
          <span>Running</span>
          <strong>{loading ? '-' : statusCounts.running || 0}</strong>
        </div>
        <div className="dashboard-metric">
          <span>Findings</span>
          <strong>{loading ? '-' : totalFindings}</strong>
        </div>
      </div>

      <div className="dashboard-grid dashboard-grid-minimal">
        <div className="dashboard-panel">
          <div className="dashboard-panel-header">
            <h2>Severity</h2>
          </div>
          <div className="severity-list">
            <div>
              <span>Critical</span>
              <strong>{loading ? '-' : findings.critical || 0}</strong>
            </div>
            <div>
              <span>High</span>
              <strong>{loading ? '-' : findings.high || 0}</strong>
            </div>
            <div>
              <span>Medium</span>
              <strong>{loading ? '-' : findings.medium || 0}</strong>
            </div>
            <div>
              <span>Low</span>
              <strong>{loading ? '-' : findings.low || 0}</strong>
            </div>
            <div>
              <span>Informational</span>
              <strong>{loading ? '-' : findings.info || 0}</strong>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

export default Dashboard
