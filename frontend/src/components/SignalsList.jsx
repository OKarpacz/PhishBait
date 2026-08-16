import '../styles/components/SignalsList.css'

const SEVERITY_CONFIG = {
  high: { label: 'High risk', className: 'severity-high' },
  medium: { label: 'Medium risk', className: 'severity-medium' },
  low: { label: 'Low risk', className: 'severity-low' },
}

function SignalsList({ signals }) {
  if (!signals || signals.length === 0) {
    return (
      <div className="signals-list signals-empty">
        No suspicious signals detected.
      </div>
    )
  }

  return (
    <div className="signals-list">
      <h3 className="signals-title">Detected signals ({signals.length})</h3>
      <ul>
        {signals.map((signal, index) => {
          const severity = SEVERITY_CONFIG[signal.severity]
          return (
            <li key={index} className="signal-item">
              <span className={`signal-badge ${severity.className}`}>
                {severity.label}
              </span>
              <div className="signal-text">
                <strong>{signal.name}</strong>
                <p>{signal.description}</p>
              </div>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

export default SignalsList