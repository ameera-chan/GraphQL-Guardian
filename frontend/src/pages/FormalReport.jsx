import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getApiErrorMessage, scanAPI } from '../utils/api'

const severitySections = [
  { key: 'CRITICAL', title: 'Critical Severity Summary' },
  { key: 'HIGH', title: 'High Severity Summary' },
  { key: 'MEDIUM', title: 'Medium Severity Summary' },
  { key: 'LOW', title: 'Low Severity Summary' },
  { key: 'INFO', title: 'Informational Severity Summary' },
]

const severityRank = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
}

function fmtDate(value) {
  if (!value) return '-'
  return new Date(value).toLocaleString()
}

function normalizeSeverity(value) {
  const severity = String(value || 'INFO').toUpperCase()
  if (severity === 'INFORMATIONAL') return 'INFO'
  return severityRank[severity] !== undefined ? severity : 'INFO'
}

function displaySeverity(value) {
  const severity = normalizeSeverity(value)
  return severity === 'INFO' ? 'Informational' : severity[0] + severity.slice(1).toLowerCase()
}

function likelihoodImpact(severity) {
  switch (normalizeSeverity(severity)) {
    case 'CRITICAL':
      return 'Likelihood: High, Impact: High'
    case 'HIGH':
      return 'Likelihood: High, Impact: Medium'
    case 'MEDIUM':
      return 'Likelihood: Medium, Impact: Medium'
    case 'LOW':
      return 'Likelihood: Low, Impact: Medium'
    default:
      return 'Likelihood: Low, Impact: Low'
  }
}

function riskLine(finding) {
  if (!finding.risk) return likelihoodImpact(finding.severity)
  return `Likelihood: ${finding.risk.likelihood_level} (${finding.risk.likelihood_score}), Impact: ${finding.risk.impact_level} (${finding.risk.impact_score})`
}

function affectedArea(finding) {
  return finding.field || finding.operation_name || finding.path || finding.category || 'GraphQL API'
}

function recommendation(finding) {
  return (
    finding.solution2 ||
    finding.solution ||
    finding.remediation ||
    'Review access, input checks, and schema exposure.'
  )
}

function splitRecommendation(value) {
  const text = String(value || '').trim()
  if (!text) return []
  const parts = text
    .split(/\s+(?=\d+\.\s)/)
    .map((item) => item.trim())
    .filter(Boolean)
  return parts.length > 1 ? parts : [text]
}

function evidenceText(finding) {
  if (finding.reproduction) return finding.reproduction
  if (finding.evidence?.reproduction) return finding.evidence.reproduction
  if (finding.evidence && Object.keys(finding.evidence).length) {
    return JSON.stringify(finding.evidence, null, 2)
  }
  return 'No proof saved.'
}

function FormalReport() {
  const { scanId } = useParams()
  const [status, setStatus] = useState(null)
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const loadReport = async () => {
      try {
        const statusData = await scanAPI.getStatus(scanId)
        setStatus(statusData)
        if (statusData.status !== 'completed') {
          setError(`Report ready after scan ends. Status: ${statusData.status}`)
          return
        }
        setReport(await scanAPI.getReport(scanId))
      } catch (err) {
        setError(getApiErrorMessage(err, 'Failed to load report'))
      } finally {
        setLoading(false)
      }
    }

    loadReport()
  }, [scanId])

  const findings = useMemo(() => {
    return (report?.findings || [])
      .slice()
      .sort((left, right) => severityRank[normalizeSeverity(left.severity)] - severityRank[normalizeSeverity(right.severity)])
  }, [report])

  const groupedFindings = useMemo(() => {
    return severitySections.reduce((groups, section) => {
      groups[section.key] = findings.filter((finding) => normalizeSeverity(finding.severity) === section.key)
      return groups
    }, {})
  }, [findings])

  if (loading) {
    return (
      <div className="formal-report-page">
        <div className="reports-panel">
          <p className="reports-muted">Loading report...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="formal-report-page">
        <div className="dashboard-alert">{error}</div>
        <Link to="/reports" className="reports-secondary-action">Back</Link>
      </div>
    )
  }

  return (
    <section className="formal-report-page" aria-label="Formal report">
      <div className="formal-report-toolbar">
        <Link to="/reports" className="reports-secondary-action">Back</Link>
        <button className="reports-primary-action" onClick={() => window.print()}>
          Export PDF
        </button>
      </div>

      <article className="formal-report-document">
        <header className="formal-report-title">
          <h1>GraphQL Security Report</h1>
          <table className="formal-meta-table">
            <tbody>
              <tr><th>Endpoint</th><td>{report.metadata?.endpoint || status?.endpoint}</td></tr>
              <tr><th>Profile</th><td>{report.metadata?.profile || 'default'}</td></tr>
              <tr><th>Scan ID</th><td>{scanId}</td></tr>
              <tr><th>Started</th><td>{fmtDate(status?.start_time)}</td></tr>
              <tr><th>Completed</th><td>{fmtDate(status?.end_time || report.metadata?.completed_at)}</td></tr>
            </tbody>
          </table>
        </header>

        <section className="formal-section">
          <h2>Summary</h2>
          <p>
            Findings by severity.
          </p>
        </section>

        {severitySections.map((section) => (
          <section className="formal-section formal-summary-section" key={section.key}>
            <h3>{section.title}</h3>
            <table className="formal-template-table">
              <thead>
                <tr>
                  <th className="formal-number-col">No.</th>
                  <th>Finding</th>
                  <th>Recommendation</th>
                </tr>
              </thead>
              <tbody>
                {(groupedFindings[section.key] || []).length ? (
                  groupedFindings[section.key].map((finding, index) => (
                    <tr key={finding.id || `${section.key}-${index}`}>
                      <td className="formal-number-col">{index + 1}</td>
                      <td>{finding.title || 'Untitled finding'}</td>
                      <td>
                        <ol className="formal-recommendation-list">
                          {splitRecommendation(recommendation(finding)).map((item, itemIndex) => (
                            <li key={`${finding.id || index}-rec-${itemIndex}`}>
                              {item.replace(/^\d+\.\s*/, '')}
                            </li>
                          ))}
                        </ol>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="3">None</td>
                  </tr>
                )}
              </tbody>
            </table>
          </section>
        ))}

        <section className="formal-section formal-details-start">
          <h2>Details</h2>
        </section>

        {findings.length ? (
          findings.map((finding, index) => (
            <section className="formal-finding-detail" key={finding.id || index}>
              <h3>{finding.title || 'Untitled finding'}</h3>
              <p className={`formal-severity-line severity-text-${normalizeSeverity(finding.severity)}`}>
                Severity: {displaySeverity(finding.severity)} ({riskLine(finding)})
              </p>
              {finding.risk?.vector && (
                <p className="formal-risk-vector">Risk vector: {finding.risk.vector}</p>
              )}

              <h4>Affected</h4>
              <ul>
                <li>{affectedArea(finding)}</li>
              </ul>

              <h4>Description</h4>
              <p>{finding.description || 'No description provided.'}</p>

              <h4>Proof</h4>
              <pre>{evidenceText(finding)}</pre>

              <h4>Fix</h4>
              <ol className="formal-recommendation-list">
                {splitRecommendation(recommendation(finding)).map((item, itemIndex) => (
                  <li key={`${finding.id || index}-solution-${itemIndex}`}>
                    {item.replace(/^\d+\.\s*/, '')}
                  </li>
                ))}
              </ol>

            </section>
          ))
        ) : (
          <p>No details.</p>
        )}

        <footer className="formal-end">[END OF REPORT]</footer>
      </article>
    </section>
  )
}

export default FormalReport
