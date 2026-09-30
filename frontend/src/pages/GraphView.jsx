import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import ReactFlow, {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  useEdgesState,
  useNodesState,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { getApiErrorMessage, scanAPI } from '../utils/api'

const nodeLabels = {
  api: 'API',
  root: 'Root',
  operation: 'Operation',
  type: 'Type',
  field: 'Field',
  argument: 'Argument',
  finding: 'Finding',
}

const severityColors = {
  CRITICAL: 'bg-red-900 text-white',
  HIGH: 'bg-red-600 text-white',
  MEDIUM: 'bg-yellow-500 text-white',
  LOW: 'bg-blue-500 text-white',
  INFO: 'bg-slate-500 text-white',
}

function CustomNode({ data }) {
  const nodeType = data.nodeType || 'type'
  return (
    <>
      <Handle type="target" position={Position.Left} />
      <div className={`schema-node schema-node-${nodeType}`}>
        <div className="schema-node-kind">{nodeLabels[nodeType] || nodeType}</div>
        <div className="schema-node-label">{data.label}</div>
        {data.meta && <div className="schema-node-meta">{data.meta}</div>}
        {data.sensitive && <div className="schema-node-flag">Sensitive</div>}
      </div>
      <Handle type="source" position={Position.Right} />
    </>
  )
}

const nodeTypes = { custom: CustomNode }

function DetailRow({ label, children, mono = false }) {
  if (children === undefined || children === null || children === '') return null
  return (
    <div className="schema-detail-row">
      <dt>{label}</dt>
      <dd className={mono ? 'schema-detail-mono' : ''}>{children}</dd>
    </div>
  )
}

function TagList({ values }) {
  if (!Array.isArray(values) || !values.length) return null
  return (
    <div className="schema-tag-list">
      {values.map((value) => <span key={value}>{value}</span>)}
    </div>
  )
}

function GraphView() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [summary, setSummary] = useState({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)
  const [search, setSearch] = useState('')
  const [operationType, setOperationType] = useState('all')
  const [showArguments, setShowArguments] = useState(false)
  const [showScalars, setShowScalars] = useState(false)
  const [showFindings, setShowFindings] = useState(true)
  const [showInfo, setShowInfo] = useState(false)

  useEffect(() => {
    const fetchGraph = async () => {
      try {
        const graphData = await scanAPI.getGraph(scanId)
        setNodes(graphData.nodes || [])
        setEdges((graphData.edges || []).map((edge) => ({
          ...edge,
          markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
        })))
        setSummary(graphData.summary || {})
      } catch (err) {
        setError(getApiErrorMessage(err, 'Failed to load schema map'))
      } finally {
        setLoading(false)
      }
    }

    fetchGraph()
  }, [scanId, setEdges, setNodes])

  const visibleNodes = useMemo(() => {
    const visibilityNodes = nodes.filter((node) => {
      const data = node.data || {}
      const nodeType = data.nodeType
      if (nodeType === 'argument' && !showArguments) return false
      if (nodeType === 'finding' && !showFindings) return false
      if (nodeType === 'finding' && data.severity === 'INFO' && !showInfo) return false
      if (nodeType === 'type' && !showScalars && ['SCALAR', 'ENUM'].includes(data.typeKind)) return false
      return true
    })

    let baseNodes = visibilityNodes
    if (operationType !== 'all') {
      const availableIds = new Set(visibilityNodes.map((node) => node.id))
      const allowedIds = new Set(
        visibilityNodes
          .filter((node) => node.data?.nodeType === 'api' || (
            node.data?.nodeType === 'root' && node.data?.operationType === operationType
          ))
          .map((node) => node.id),
      )
      const queue = visibilityNodes
        .filter((node) => node.data?.nodeType === 'operation' && node.data?.operationType === operationType)
        .map((node) => node.id)
      queue.forEach((id) => allowedIds.add(id))

      for (let index = 0; index < queue.length; index += 1) {
        const source = queue[index]
        edges.forEach((edge) => {
          if (edge.source !== source || !availableIds.has(edge.target) || allowedIds.has(edge.target)) return
          const target = nodes.find((node) => node.id === edge.target)
          if (['root', 'operation'].includes(target?.data?.nodeType) && target?.data?.operationType !== operationType) return
          allowedIds.add(edge.target)
          queue.push(edge.target)
        })
      }
      baseNodes = visibilityNodes.filter((node) => allowedIds.has(node.id))
    }

    const term = search.trim().toLowerCase()
    if (!term) return baseNodes

    const baseIds = new Set(baseNodes.map((node) => node.id))
    const matches = new Set(
      baseNodes
        .filter((node) => (node.data?.searchText || node.data?.label || '').toLowerCase().includes(term))
        .map((node) => node.id),
    )
    const related = new Set(matches)
    edges.forEach((edge) => {
      if (matches.has(edge.source) && baseIds.has(edge.target)) related.add(edge.target)
      if (matches.has(edge.target) && baseIds.has(edge.source)) related.add(edge.source)
    })
    return baseNodes.filter((node) => related.has(node.id))
  }, [edges, nodes, operationType, search, showArguments, showFindings, showInfo, showScalars])

  const visibleEdges = useMemo(() => {
    const visibleIds = new Set(visibleNodes.map((node) => node.id))
    return edges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target))
  }, [edges, visibleNodes])

  useEffect(() => {
    if (selectedNode && !visibleNodes.some((node) => node.id === selectedNode.id)) {
      setSelectedNode(null)
    }
  }, [selectedNode, visibleNodes])

  const onNodeClick = useCallback((event, node) => setSelectedNode(node), [])

  if (loading) {
    return (
      <div className="schema-map-state">
        <p>Loading schema relationships...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="schema-map-state">
        <div className="dashboard-alert">{error}</div>
        <button onClick={() => navigate(`/results/${scanId}`)} className="schema-map-back">
          Back to Results
        </button>
      </div>
    )
  }

  const data = selectedNode?.data || {}

  return (
    <div className="schema-map-page">
      <div className="schema-map-header">
        <div>
          <h2>Schema Map</h2>
        </div>
        <button onClick={() => navigate(`/results/${scanId}`)} className="schema-map-back">
          Back to Results
        </button>
      </div>

      <div className="schema-map-toolbar">
        <label className="schema-map-search">
          <span>Search</span>
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Operation, type, field, or finding"
          />
        </label>

        <label className="schema-map-select">
          <span>Operation</span>
          <select value={operationType} onChange={(event) => setOperationType(event.target.value)}>
            <option value="all">All</option>
            <option value="query">Queries</option>
            <option value="mutation">Mutations</option>
            <option value="subscription">Subscriptions</option>
          </select>
        </label>

        <div className="schema-map-toggles" aria-label="Schema map visibility">
          <button type="button" className={showArguments ? 'active' : ''} onClick={() => setShowArguments((value) => !value)}>
            Arguments
          </button>
          <button type="button" className={showScalars ? 'active' : ''} onClick={() => setShowScalars((value) => !value)}>
            Scalars
          </button>
          <button type="button" className={showFindings ? 'active' : ''} onClick={() => setShowFindings((value) => !value)}>
            Findings
          </button>
          <button type="button" className={showInfo ? 'active' : ''} onClick={() => setShowInfo((value) => !value)} disabled={!showFindings}>
            Info
          </button>
        </div>

        <div className="schema-map-count">
          <strong>{visibleNodes.length}</strong>
          <span>of {summary.total_nodes || nodes.length} nodes</span>
        </div>
      </div>

      <div className="schema-map-legend" aria-label="Node legend">
        {['api', 'root', 'operation', 'type', 'field', 'argument', 'finding'].map((type) => (
          <span key={type} className={`legend-${type}`}>{nodeLabels[type]}</span>
        ))}
      </div>

      <div className="schema-map-body">
        <div className="schema-map-canvas">
          {visibleNodes.length ? (
            <ReactFlow
              nodes={visibleNodes}
              edges={visibleEdges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onNodeClick={onNodeClick}
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{ padding: 0.16 }}
              minZoom={0.08}
              maxZoom={2}
            >
              <Background color="#E2E8F0" gap={18} />
              <Controls />
              <MiniMap nodeColor={getMapNodeColor} position="bottom-right" pannable zoomable />
            </ReactFlow>
          ) : (
            <div className="schema-map-empty">No nodes match the current filters.</div>
          )}
        </div>

        {selectedNode && (
          <aside className="schema-map-details">
            <div className="schema-map-details-header">
              <div>
                <span>{nodeLabels[data.nodeType] || data.nodeType}</span>
                <h3>{data.label}</h3>
              </div>
              <button type="button" onClick={() => setSelectedNode(null)} aria-label="Close details">×</button>
            </div>

            <div className="schema-map-details-body">
              {data.severity && <span className={`schema-severity ${severityColors[data.severity] || severityColors.INFO}`}>{data.severity}</span>}

              <dl>
                <DetailRow label="Endpoint" mono>{data.endpoint}</DetailRow>
                <DetailRow label="Schema source">{data.schemaSource}</DetailRow>
                <DetailRow label="Operation" mono>{data.operationName}</DetailRow>
                <DetailRow label="Operation type">{data.operationType}</DetailRow>
                <DetailRow label="Root type" mono>{data.rootType}</DetailRow>
                <DetailRow label="Type kind">{data.typeKind}</DetailRow>
                <DetailRow label="Returns" mono>{data.returnType || data.fieldType}</DetailRow>
                <DetailRow label="Field path" mono>{data.fullField}</DetailRow>
                <DetailRow label="Owner" mono>{data.owner}</DetailRow>
                <DetailRow label="Argument type" mono>{data.argumentType}</DetailRow>
                <DetailRow label="Required">{data.required === true ? 'Yes' : data.required === false ? 'No' : null}</DetailRow>
                <DetailRow label="Risk score">{data.riskScore}</DetailRow>
                <DetailRow label="Rule" mono>{data.ruleId}</DetailRow>
                <DetailRow label="Category">{data.category}</DetailRow>
                <DetailRow label="State">{data.state}</DetailRow>
                <DetailRow label="Confidence">{data.confidence}</DetailRow>
                <DetailRow label="Fields">{data.fieldCount}</DetailRow>
                <DetailRow label="Review score">{data.reviewScore}</DetailRow>
                <DetailRow label="Disposition">{data.disposition}</DetailRow>
              </dl>

              {data.tags?.length > 0 && <section><h4>Security tags</h4><TagList values={data.tags} /></section>}
              {data.matchedKeywords?.length > 0 && <section><h4>Sensitive matches</h4><TagList values={data.matchedKeywords} /></section>}
              {data.arguments?.length > 0 && (
                <section>
                  <h4>Arguments</h4>
                  <div className="schema-argument-list">
                    {data.arguments.map((argument) => (
                      <div key={`${argument.name}-${argument.type}`}>
                        <code>{argument.name}</code>
                        <span>{argument.type}</span>
                      </div>
                    ))}
                  </div>
                </section>
              )}
              {data.description && <section><h4>Description</h4><p>{data.description}</p></section>}
              {data.recommendedFocus && <section><h4>Verification focus</h4><p>{data.recommendedFocus}</p></section>}
              {data.operation && <section><h4>Generated operation</h4><pre>{data.operation}</pre></section>}
              {data.reproduction && <section><h4>Reproduce</h4><pre>{data.reproduction}</pre></section>}
              {data.evidence && <section><h4>Evidence</h4><pre>{formatValue(data.evidence)}</pre></section>}
              {data.remediation && <section><h4>Remediation</h4><p>{data.remediation}</p></section>}
            </div>
          </aside>
        )}
      </div>
    </div>
  )
}

function getMapNodeColor(node) {
  const colors = {
    api: '#111827',
    root: '#2563EB',
    operation: '#93C5FD',
    type: '#818CF8',
    field: '#F59E0B',
    argument: '#94A3B8',
    finding: '#EF4444',
  }
  return colors[node.data?.nodeType] || '#CBD5E1'
}

function formatValue(value) {
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2)
}

export default GraphView
