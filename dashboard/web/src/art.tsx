/* Inline SVG art for the gates board.
 *
 * Inline on purpose: no extra network requests, no CDN, and the strokes
 * inherit the Cloudscape dark palette so the art can never drift from the
 * theme. Every graphic carries role="img" + <title> for screen readers.
 */

// Cloudscape dark-mode status/accent tokens (kept in one place).
const C = {
  ink: "#0f1b2d",
  line: "#414d5c",
  dim: "#8d99a8",
  text: "#d1d5db",
  blue: "#539fe5",
  green: "#6aaf35",
  red: "#eb6f6f",
  amber: "#e07941",
  purple: "#a97bd6",
  wood: "#a5713a",
};

/** Per-seat sigil. Four SOLID silhouettes — shield, bolt, triangle, disc.
 *
 * These were outline strokes (1.6 in a 24 viewBox) drawn at 13-15px, where the
 * stroke lands near one pixel and every seat reads as "small outlined shape".
 * The only thing that actually separated them at that size was colour, which is
 * the exact failure A11Y-004 exists to catch — so the panel's own dashboard was
 * breaking the panel's own rule. Filled shapes with distinct OUTER silhouettes
 * survive monochrome at 14px; colour is now a second cue, not the only one.
 *
 * Pass `label` where the sigil is the only carrier of which seat spoke (the
 * inline-findings row shows a rule id, not an agent name) so the glyph is not
 * mute to a screen reader.
 */
export function PersonaSigil({ name, size = 18, label = false }:
    { name: string; size?: number; label?: boolean }) {
  const common = { width: size, height: size, viewBox: "0 0 24 24" as const,
    role: "img" as const,
    ...(label ? { "aria-label": name } : { "aria-hidden": true as const }) };
  if (name === "Security Review Agent") {
    // shield silhouette
    return (
      <svg {...common}>
        <path d="M12 1.8 21 5.2v6.4c0 5.4-3.7 9.4-9 11.3-5.3-1.9-9-5.9-9-11.3V5.2z"
          fill={C.red} />
        <path d="M7.9 12.1 10.9 15.2 16.6 8.9" fill="none" stroke={C.ink}
          strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  if (name === "Code Quality Review Agent") {
    // bolt silhouette
    return (
      <svg {...common}>
        <path d="M14.4 1 3.6 14.2h6.2L8.2 23 20.4 9.1h-6.6z" fill={C.amber} />
      </svg>
    );
  }
  if (name === "Accessibility Review Agent") {
    // disc silhouette with a figure knocked out of it
    return (
      <svg {...common}>
        <circle cx="12" cy="12" r="10.4" fill={C.green} />
        <circle cx="12" cy="6.4" r="2" fill={C.ink} />
        <path d="M5.9 9.9h12.2M12 9.9V16M12 16l-3.4 5M12 16l3.4 5"
          fill="none" stroke={C.ink} strokeWidth="2.2" strokeLinecap="round" />
      </svg>
    );
  }
  // Architecture — triangle (set-square) silhouette
  return (
    <svg {...common}>
      <path d="M2.4 21.2 12 2.6l9.6 18.6z" fill={C.purple} />
      <path d="M12 9.4v7.4" fill="none" stroke={C.ink} strokeWidth="2.2"
        strokeLinecap="round" />
    </svg>
  );
}

/** The artifact's Troy horse mark. */
export function HorseMark({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" role="img"
      aria-label="The Fall of Troy — the deployed artifact">
      <title>The deployed artifact</title>
      {/* blocky, to echo the 16-bit scene */}
      <rect x="4" y="12" width="12" height="6" fill={C.wood} />
      <rect x="14" y="6" width="4" height="7" fill={C.wood} />
      <rect x="17" y="4" width="4" height="4" fill={C.wood} />
      <rect x="19.5" y="5" width="1.4" height="1.4" fill={C.ink} />
      <rect x="5" y="18" width="2" height="4" fill={C.wood} opacity="0.85" />
      <rect x="13" y="18" width="2" height="4" fill={C.wood} opacity="0.85" />
      <rect x="3" y="10.6" width="14" height="1.6" fill="#c08a4a" />
    </svg>
  );
}
