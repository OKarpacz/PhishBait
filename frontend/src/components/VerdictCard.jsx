import '../styles/components/VerdictCard.css'
import ProbabilityBar from './ProbabilityBar'


const VERDICT_CONFIG = {
  safe: { label: 'Safe', className: 'verdict-safe' },
  suspicious: { label: 'Suspicious', className: 'verdict-suspicious' },
  dangerous: { label: 'Dangerous', className: 'verdict-dangerous' },
}

function VerdictCard({ result }) {
  const config = VERDICT_CONFIG[result.verdict]

  return (
    <section className={`verdict-card ${config.className}`}>
      <div className="verdict-label-top">{config.label}</div>

      <ProbabilityBar probability={result.phishing_probability} />

      <p className="verdict-summary">{result.summary}</p>

      {result.analyzed_url && (
        <p className="verdict-analyzed-url">
          Checked link: <code>{result.analyzed_url}</code>
        </p>
      )}
    </section>
  )
}

export default VerdictCard