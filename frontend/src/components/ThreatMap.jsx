import { useEffect, useState } from 'react'
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps'
import '../styles/components/ThreatMap.css'


const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'

const ATTACK_ORIGINS = [
  { name: 'São Paulo', coords: [-46.63, -23.55] },
  { name: 'Lagos', coords: [3.38, 6.45] },
  { name: 'Moscow', coords: [37.62, 55.75] },
  { name: 'Jakarta', coords: [106.85, -6.21] },
  { name: 'Mumbai', coords: [72.88, 19.08] },
  { name: 'Warsaw', coords: [21.01, 52.23] },
  { name: 'Bucharest', coords: [26.10, 44.44] },
  { name: 'Ho Chi Minh City', coords: [106.63, 10.82] },
  { name: 'Manila', coords: [120.98, 14.60] },
  { name: 'Bogotá', coords: [-74.08, 4.71] },
  { name: 'Karachi', coords: [67.01, 24.86] },
  { name: 'Kyiv', coords: [30.52, 50.45] },
  { name: 'Lahore', coords: [74.36, 31.55] },
  { name: 'Tehran', coords: [51.39, 35.69] },
  { name: 'Bangkok', coords: [100.50, 13.76] },
]

const MAX_ACTIVE_PINGS = 6
const SPAWN_INTERVAL_MS = 1800
const PING_LIFETIME_MS = 3200

let pingIdCounter = 0

function randomOrigin() {
  return ATTACK_ORIGINS[Math.floor(Math.random() * ATTACK_ORIGINS.length)]
}

function ThreatMap() {
  const [pings, setPings] = useState([])

  useEffect(() => {
    const interval = setInterval(() => {
      setPings((current) => {
        if (current.length >= MAX_ACTIVE_PINGS) return current
        const origin = randomOrigin()
        const newPing = { id: pingIdCounter++, ...origin }
        return [...current, newPing]
      })
    }, SPAWN_INTERVAL_MS)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    if (pings.length === 0) return
    const timers = pings.map((ping) =>
      setTimeout(() => {
        setPings((current) => current.filter((p) => p.id !== ping.id))
      }, PING_LIFETIME_MS)
    )
    return () => timers.forEach(clearTimeout)
  }, [pings])

  return (
    <div className="threat-map">
      <ComposableMap
        projectionConfig={{ scale: 220 }}
        className="threat-map-svg"
      >
        <Geographies geography={GEO_URL}>
          {({ geographies }) =>
            geographies.map((geo) => (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                className="threat-map-country"
              />
            ))
          }
        </Geographies>

        {pings.map((ping) => (
          <Marker key={ping.id} coordinates={ping.coords}>
            <circle r={3} className="ping-dot" />
            <circle r={3} className="ping-ring" />
          </Marker>
        ))}
      </ComposableMap>

      <div className="threat-map-overlay" aria-hidden="true" />
    </div>
  )
}

export default ThreatMap
