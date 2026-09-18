/** Inline stroke icons — no icon library dependency, tree-shakeable by definition. */

type IconProps = { className?: string }

const base = (className?: string) => ({
  className: className ?? 'size-4',
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.8,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
  'aria-hidden': true,
})

export const IconGauge = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM13.4 10.6 19 5M3.3 17A9 9 0 1 1 20.7 17" />
  </svg>
)

export const IconUsers = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />
  </svg>
)

export const IconAlert = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0ZM12 9v4M12 17h.01" />
  </svg>
)

export const IconFolder = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z" />
  </svg>
)

export const IconRadar = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M19.07 4.93A10 10 0 0 0 6.99 3.34M4 6h.01M2.29 9.62a10 10 0 1 0 19.42 0M12 12v.01M15.5 8.5a5 5 0 1 0 1.5 6.5" />
  </svg>
)

export const IconShield = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1Z" />
  </svg>
)

export const IconFlask = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M10 2v7.31M14 9.3V1.99M8.5 2h7M14 9.3a6.5 6.5 0 1 1-4 0M5.58 16.5h12.85" />
  </svg>
)

export const IconDatabase = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <ellipse cx="12" cy="5" rx="9" ry="3" />
    <path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3" />
  </svg>
)

export const IconChart = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M3 3v16a2 2 0 0 0 2 2h16M7 16l4-6 4 3 5-7" />
  </svg>
)

export const IconSettings = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z" />
  </svg>
)

export const IconSearch = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <circle cx="11" cy="11" r="8" />
    <path d="m21 21-4.3-4.3" />
  </svg>
)

export const IconBolt = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M13 2 3 14h9l-1 8 10-12h-9l1-8Z" />
  </svg>
)

export const IconClock = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <circle cx="12" cy="12" r="10" />
    <path d="M12 6v6l4 2" />
  </svg>
)

export const IconDownload = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" />
  </svg>
)

export const IconCheck = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M20 6 9 17l-5-5" />
  </svg>
)

export const IconX = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M18 6 6 18M6 6l12 12" />
  </svg>
)

export const IconChevronRight = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="m9 18 6-6-6-6" />
  </svg>
)

export const IconArrowUp = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M12 19V5M5 12l7-7 7 7" />
  </svg>
)

export const IconArrowDown = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M12 5v14M19 12l-7 7-7-7" />
  </svg>
)

export const IconSparkle = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1" />
    <circle cx="12" cy="12" r="3" />
  </svg>
)

export const IconGlobe = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <circle cx="12" cy="12" r="10" />
    <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10Z" />
  </svg>
)

export const IconKey = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="m15.5 7.5 3 3L22 7l-3-3M2 22l5.5-5.5" />
    <circle cx="16.5" cy="7.5" r="0" />
    <path d="M12.5 11.5 15.5 7.5M9.5 20a5.5 5.5 0 1 1 0-11 5.5 5.5 0 0 1 0 11Z" />
  </svg>
)

export const IconLogout = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" />
  </svg>
)

export const IconPlay = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="m6 3 14 9-14 9V3Z" />
  </svg>
)

export const IconRefresh = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M3 12a9 9 0 0 1 15-6.7L21 8M21 3v5h-5M21 12a9 9 0 0 1-15 6.7L3 16M3 21v-5h5" />
  </svg>
)

export const IconLock = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <rect x="3" y="11" width="18" height="11" rx="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </svg>
)

export const IconEye = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
)

export const IconFilter = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3Z" />
  </svg>
)

export const IconPulse = ({ className }: IconProps) => (
  <svg {...base(className)}>
    <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
  </svg>
)
