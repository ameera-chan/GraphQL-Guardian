import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { getApiErrorMessage, scanAPI } from '../utils/api'

const severityStyles = {
  CRITICAL: 'bg-red-200 text-red-950 border-red-400',
  HIGH: 'bg-red-100 text-red-800 border-red-200',
  MEDIUM: 'bg-amber-100 text-amber-800 border-amber-200',
  LOW: 'bg-blue-100 text-blue-800 border-blue-200',
  INFO: 'bg-slate-100 text-slate-700 border-slate-200',
}

const statusStyles = {
  completed: 'bg-emerald-100 text-emerald-800',
  running: 'bg-blue-100 text-blue-800',
  failed: 'bg-red-100 text-red-800',
  skipped: 'bg-slate-100 text-slate-700',
  pending: 'bg-slate-100 text-slate-700',
}

function Pill({ children, className = '' }) {
  return (
    <span className={`inline-flex items-center rounded border px-2 py-1 text-xs font-semibold ${className}`}>
      {children}
    </span>
  )
}

function ResultsView() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [status, setStatus] = useState(null)
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('all')
  const [selectedFindingId, setSelectedFindingId] = useState(null)
  const [activeSection, setActiveSection] = useState('flow')

  useEffect(() => {
    let cancelled = false
    let timer = null

    const pollStatus = async () => {
      try {
        const statusData = await scanAPI.getStatus(scanId)
        if (cancelled) return
        setStatus(statusData)

        if (statusData.status === 'completed') {
          const reportData = await scanAPI.getReport(scanId)
          if (cancelled) return
          setReport(reportData)
          setLoading(false)
        } else if (statusData.status === 'failed') {
          setError(statusData.error || 'Scan failed')
          setLoading(false)
        } else {
          timer = window.setTimeout(pollStatus, 2000)
        }
      } catch (err) {
        if (cancelled) return
        setError(getApiErrorMessage(err, 'Failed to fetch scan status'))
        setLoading(false)
      }
    }

    pollStatus()
    return () => {
      cancelled = true
      if (timer) window.clearTimeout(timer)
    }
  }, [scanId])

  const findings = useMemo(() => report?.findings || [], [report?.findings])
  const workflow = report?.workflow || []
  const filteredFindings = useMemo(() => {
    if (filter === 'all') return findings
    return findings.filter((finding) => finding.severity === filter)
  }, [findings, filter])
  const selectedFinding = useMemo(() => {
    if (!filteredFindings.length) return null
    return filteredFindings.find((finding) => finding.id === selectedFindingId) || filteredFindings[0]
  }, [filteredFindings, selectedFindingId])

  if (error) {
    return (
      <div className="max-w-4xl mx-auto">
        <div className="dashboard-alert" role="status">
          {error}
        </div>
        <button onClick={() => navigate('/scans')} className="reports-primary-action">
          New Scan
        </button>
      </div>
    )
  }

  if (loading || !report) {
    return (
      <div className="max-w-4xl mx-auto">
        <div className="reports-panel p-6">
          <h2 className="text-2xl font-bold mb-4">Scan Running</h2>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div
              className="bg-blue-600 h-2 rounded-full transition-all duration-500"
              style={{ width: `${(status?.progress || 0) * 100}%` }}
            />
          </div>
          <p className="mt-4 text-gray-600">{status?.phase || status?.status || 'Queued'}</p>
        </div>
      </div>
    )
  }

  const summary = report.summary || {}

  return (
    <div className="results-page">
      <div className="results-header-block">
        <div>
          <h1>Scan Results</h1>
          <div className="results-meta">
            <p>
              <strong>ENDPOINT:</strong>
              <span>{report.metadata?.endpoint}</span>
            </p>
            <p>
              <strong>PROFILE:</strong>
              <span>{report.metadata?.profile || 'Default'}</span>
            </p>
          </div>
        </div>
        <div className="results-actions">
          <Link to={`/reports/${scanId}`}>Report</Link>
          <Link to={`/graph/${scanId}`}>Schema</Link>
        </div>
      </div>

      <section className="results-summary-grid">
        <Metric label="Total" value={summary.total || 0} />
        <Metric label="Critical" value={summary.critical || 0} />
        <Metric label="High" value={summary.high || 0} />
        <Metric label="Medium" value={summary.medium || 0} />
        <Metric label="Low" value={summary.low || 0} />
        <Metric label="Info" value={summary.info || 0} />
      </section>

      <nav className="results-section-tabs" aria-label="Scan results sections">
        <button
          type="button"
          className={activeSection === 'flow' ? 'active' : ''}
          onClick={() => setActiveSection('flow')}
        >
          Scan Flow
        </button>
        <button
          type="button"
          className={activeSection === 'findings' ? 'active' : ''}
          onClick={() => setActiveSection('findings')}
        >
          Findings
        </button>
      </nav>

      {activeSection === 'flow' ? (
        <section className="results-flow-panel">
          <div className="results-flow-header">
            <h3>Scan Flow</h3>
            <span>{report.metadata?.duration_seconds || 0}s</span>
          </div>
          <div className="results-flow-grid">
            {workflow.map((phase) => (
              <article key={phase.name} className="results-flow-card">
                <h4>{phase.name}</h4>
                <p>{phase.error || phase.summary?.reason || `${phase.duration_seconds || 0}s`}</p>
                <span className={`results-flow-status ${statusStyles[phase.status] || statusStyles.pending}`}>
                  {phase.status}
                </span>
              </article>
            ))}
          </div>
        </section>
      ) : (
        <section className="results-findings-panel">
          <div className="results-findings-header">
            <h2>Findings</h2>
            <div className="results-filter">
              {['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((item) => (
                <button
                  key={item}
                  onClick={() => setFilter(item)}
                  className={filter === item ? 'active' : ''}
                >
                  {item === 'all' ? 'All' : item}
                </button>
              ))}
            </div>
          </div>

          <div className="results-findings-body">
            <div className="results-finding-list">
              {filteredFindings.map((finding) => (
                <button
                  key={finding.id}
                  type="button"
                  className={`results-finding-row${selectedFinding?.id === finding.id ? ' active' : ''}`}
                  onClick={() => setSelectedFindingId(finding.id)}
                >
                  <Pill className={severityStyles[finding.severity] || severityStyles.INFO}>
                    {finding.severity}
                  </Pill>
                  <span>{finding.title}</span>
                </button>
              ))}
              {!filteredFindings.length && <p className="results-empty-text">No findings.</p>}
            </div>

            <aside className="results-detail-card">
              {selectedFinding ? (
                <div className="results-detail">
                  <div className="results-detail-title-row">
                    <h3>{selectedFinding.title}</h3>
                    <Pill className={severityStyles[selectedFinding.severity] || severityStyles.INFO}>
                      {selectedFinding.severity}
                    </Pill>
                  </div>
                  <p>{selectedFinding.description}</p>
                  <dl>
                    <div>
                      <dt>Category</dt>
                      <dd>{selectedFinding.category || 'N/A'}</dd>
                    </div>
                    <div>
                      <dt>Rule</dt>
                      <dd>{selectedFinding.rule_id || 'N/A'}</dd>
                    </div>
                    <div>
                      <dt>Likelihood</dt>
                      <dd>{selectedFinding.risk?.likelihood_level || 'N/A'}</dd>
                    </div>
                    <div>
                      <dt>Impact</dt>
                      <dd>{selectedFinding.risk?.impact_level || 'N/A'}</dd>
                    </div>
                  </dl>
                  {selectedFinding.remediation && (
                    <>
                      <h4>Remediations</h4>
                      <p>{selectedFinding.remediation}</p>
                    </>
                  )}
                  {selectedFinding.reproduction && (
                    <>
                      <h4>Reproduce</h4>
                      <pre>{selectedFinding.reproduction}</pre>
                    </>
                  )}
                </div>
              ) : (
                <p className="results-empty-text">Select a finding.</p>
              )}
            </aside>
          </div>
        </section>
      )}
    </div>
  )
}

function Metric({ label, value }) {
  return (
    <div className="results-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

export default ResultsView
