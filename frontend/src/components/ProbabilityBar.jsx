import { useEffect, useRef, useState } from 'react'
import '../styles/components/ProbabilityBar.css'

function severityClassFor(probability) {
  if (probability < 30) return 'ring-safe'
  if (probability < 65) return 'ring-suspicious'
  return 'ring-dangerous'
}

const RADIUS = 54
const STROKE = 10
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

function ProbabilityBar({ probability }) {
  const [animated, setAnimated] = useState(0)
  const frameRef = useRef()

  useEffect(() => {
    const start = performance.now()
    const duration = 900

    function tick(now) {
      const elapsed = now - start
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setAnimated(probability * eased)
      if (progress < 1) {
        frameRef.current = requestAnimationFrame(tick)
      }
    }

    frameRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frameRef.current)
  }, [probability])

  const severityClass = severityClassFor(probability)
  const offset = CIRCUMFERENCE * (1 - animated / 100)

  return (
    <div className="probability-ring-wrapper">
      <div className="probability-ring">
        <svg width="140" height="140" viewBox="0 0 140 140">
          <circle
            cx="70"
            cy="70"
            r={RADIUS}
            className="ring-track"
            strokeWidth={STROKE}
            fill="none"
          />
          <circle
            cx="70"
            cy="70"
            r={RADIUS}
            className={`ring-fill ${severityClass}`}
            strokeWidth={STROKE}
            fill="none"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={offset}
            strokeLinecap="round"
            transform="rotate(-90 70 70)"
          />
        </svg>
        <div className="ring-center-value">{Math.round(animated)}%</div>
      </div>
    </div>
  )
}

export default ProbabilityBar