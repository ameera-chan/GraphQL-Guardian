import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getApiErrorMessage, scanAPI } from '../utils/api'

function ScanHistory() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [deleteError, setDeleteError] = useState(null)

  useEffect(() => {
    async function loadScans() {
      try {
        const scansData = await scanAPI.listScans(20, 0)
        setScans(scansData.scans)
      } catch (err) {
        setError(getApiErrorMessage(err, 'Failed to load reports'))
      } finally {
        setLoading(false)
      }
    }

    loadScans()
  }, [])

  const handleDelete = async (scanId) => {
    if (!confirm('Delete this scan?')) return

    try {
      setDeleteError(null)
      await scanAPI.deleteScan(scanId)
      setScans(scans.filter((scan) => scan.id !== scanId))
    } catch (err) {
      setDeleteError(getApiErrorMessage(err, 'Delete failed'))
    }
  }

  const formatDate = (value) => new Date(value).toLocaleString()

  if (loading) {
    return (
      <div className="reports-page">
        <div className="reports-panel">
          <p className="reports-muted">Loading reports...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="reports-page">
        <div className="dashboard-alert">{error}</div>
      </div>
    )
  }

  return (
    <section className="reports-page" aria-label="Scan reports">
      <div className="reports-header-block">
        <div>
          <h1>Reports</h1>
        </div>
        <div className="reports-actions">
          <Link to="/scans" className="reports-primary-action">
            New Scan
          </Link>
        </div>
      </div>

      {deleteError && (
        <div className="dashboard-alert" role="status">
          {deleteError}
        </div>
      )}

      <div className="reports-panel">
        <div className="reports-table-wrap">
          <table className="reports-table">
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>Status</th>
                <th>Started</th>
                <th>Completed</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id}>
                  <td>
                    <span className="reports-endpoint">{scan.endpoint}</span>
                  </td>
                  <td>
                    <span className={`scan-status scan-status-${scan.status}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td>{formatDate(scan.start_time)}</td>
                  <td>{scan.end_time ? formatDate(scan.end_time) : '-'}</td>
                  <td>
                    <div className="reports-row-actions">
                      {scan.status === 'completed' && (
                        <>
                          <Link to={`/reports/${scan.id}`}>Report</Link>
                          <Link to={`/graph/${scan.id}`}>Schema</Link>
                        </>
                      )}
                      {scan.status === 'running' && (
                        <Link to={`/results/${scan.id}`}>Status</Link>
                      )}
                      <button onClick={() => handleDelete(scan.id)} disabled={scan.status === 'running'}>
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {scans.length === 0 && (
          <div className="reports-empty">
            No reports yet. <Link to="/scans">Start scan</Link>
          </div>
        )}
      </div>
    </section>
  )
}

export default ScanHistory
