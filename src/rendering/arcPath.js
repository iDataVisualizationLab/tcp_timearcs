// src/rendering/arcPath.js
// Arc path generation

/**
 * Generate SVG arc path for a link.
 * @param {Object} d - Link with source/target having x/y properties
 * @returns {string} - SVG path string
 */
export function linkArc(d) {
  if (!d || !d.source || !d.target) {
    console.warn('Invalid link object for arc:', d);
    return 'M0,0 L0,0';
  }
  const dx = d.target.x - d.source.x;
  const dy = d.target.y - d.source.y;
  const dr = Math.sqrt(dx * dx + dy * dy) / 2;
  if (d.source.y < d.target.y) {
    return "M" + d.source.x + "," + d.source.y + "A" + dr + "," + dr + " 0 0,1 " + d.target.x + "," + d.target.y;
  } else {
    return "M" + d.target.x + "," + d.target.y + "A" + dr + "," + dr + " 0 0,1 " + d.source.x + "," + d.source.y;
  }
}

/**
 * Generate gradient ID for a link.
 * @param {Object} d - Link object
 * @param {Function} sanitizeId - ID sanitizer function
 * @returns {string}
 */
export function gradientIdForLink(d, sanitizeId) {
  const src = d.sourceIp || (typeof d.source === 'string' ? d.source : d.source?.name);
  const tgt = d.targetIp || (typeof d.target === 'string' ? d.target : d.target?.name);
  return `grad-${sanitizeId(`${src}__${tgt}__${d.minute}`)}`;
}
