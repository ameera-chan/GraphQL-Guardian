import { Link, Route, Routes, useLocation } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import ScanForm from './pages/ScanForm'
import ScanHistory from './pages/ScanHistory'
import ResultsView from './pages/ResultsView'
import GraphView from './pages/GraphView'
import FormalReport from './pages/FormalReport'
import ErrorBoundary from './components/ErrorBoundary'

function App() {
  const location = useLocation()
  const navItems = [
    { to: '/', label: 'Dashboard', match: (path) => path === '/' },
    { to: '/scans', label: 'Scans', match: (path) => path.startsWith('/scans') || path.startsWith('/results') || path.startsWith('/graph') },
    { to: '/reports', label: 'Reports', match: (path) => path.startsWith('/reports') },
  ]

  return (
    <div className="guardql-shell">
      <header className="guardql-header">
        <Link to="/" className="guardql-logo" aria-label="guardql dashboard">
          <span>guard</span>
          <span className="logo-q">q</span>
          <span className="logo-l">l</span>
        </Link>
      </header>

      <div className="guardql-body">
        <aside className="guardql-sidebar" aria-label="Primary navigation">
          <nav className="guardql-nav">
            {navItems.map((item) => {
              const active = item.match(location.pathname)
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={`guardql-nav-item${active ? ' active' : ''}`}
                >
                  {item.label}
                </Link>
              )
            })}
          </nav>
        </aside>

        <main className="guardql-content">
          <ErrorBoundary resetKey={location.pathname}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/scans" element={<ScanForm />} />
              <Route path="/reports" element={<ScanHistory />} />
              <Route path="/reports/:scanId" element={<FormalReport />} />
              <Route path="/results/:scanId" element={<ResultsView />} />
              <Route path="/graph/:scanId" element={<GraphView />} />
            </Routes>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  )
}

export default App
