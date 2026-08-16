import { useState } from 'react'
import './styles/App.css'
import VerdictCard from './components/VerdictCard'
import SignalsList from './components/SignalsList'
import ThreatMap from './components/ThreatMap'


const MODES = {
  url: { label: 'Link (URL)', placeholder: 'https://example.com/login', rows: 3 },
  email: { label: 'Email Content', placeholder: 'Paste the entire email content (headers, links, body)...', rows: 8 },
}

function App() {
  const [mode, setMode] = useState('url')
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  async function handleSubmit(e) {
    e.preventDefault()
    setError(null)
    setResult(null)

    if (!content.trim()) {
      setError('Please paste a URL or email content first.')
      return
    }

    setLoading(true)
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input_type: mode, content }),
      })

      if (!response.ok) {
        throw new Error(`Backend returned an error (${response.status})`)
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError('Failed to connect to the backend. Please check if the API server is running.')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  function switchMode(nextMode) {
    setMode(nextMode)
    setResult(null)
    setError(null)
  }

  return (
    <div className="page">
      <ThreatMap />

      <main className="app">
        <div className="eyebrow">Live threat monitoring</div>
        <h1>Check if this is phishing</h1>
        <p className="subtitle">Paste a link or the content of a suspicious email.</p>

        <div className="glass-card">
          <div className="tabs" role="tablist">
            {Object.entries(MODES).map(([key, config]) => (
              <button
                key={key}
                type="button"
                role="tab"
                aria-selected={mode === key}
                className={`tab ${mode === key ? 'active' : ''}`}
                onClick={() => switchMode(key)}
              >
                {config.label}
              </button>
            ))}
          </div>

          <form onSubmit={handleSubmit}>
            <textarea
              className="input-field"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder={MODES[mode].placeholder}
              rows={MODES[mode].rows}
            />
            <button type="submit" className="submit-btn" disabled={loading}>
              {loading ? 'Checking...' : 'Check'}
            </button>
          </form>

          {error && <p className="error">{error}</p>}
        </div>

        {result && <VerdictCard result={result} />}

        {result && <SignalsList signals={result.signals} />}

        {result && (
          <details className="raw-details">
            <summary>Raw API Response (debug)</summary>
            <pre className="result-raw">{JSON.stringify(result, null, 2)}</pre>
          </details>
        )}
      </main>
    </div>
  )
}

export default App
