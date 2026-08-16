import '../styles/components/ProbabilityBar.css'

function severityClassFor(probability) {
  if (probability < 30) return 'bar-safe'
  if (probability < 65) return 'bar-suspicious'
  return 'bar-dangerous'
}

function ProbabilityBar({ probability }) {
  const colorClass = severityClassFor(probability)

  return (
    <div className="probability-bar">
      <div className="probability-label">
        <span>Phishing probability</span>
        <strong>{probability}%</strong>
      </div>
      <div className="probability-track">
        <div
          className={`probability-fill ${colorClass}`}
          style={{ width: `${probability}%` }}
        />
      </div>
    </div>
  )
}

export default ProbabilityBar