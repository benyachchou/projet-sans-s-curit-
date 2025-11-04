// Service d'intégration CVE externe (CVE.org). Utilise fetch (Node >=18).
// Documentation CVE 5.x: les champs sont dans containers.cna.* et cveMetadata.*
// On mappe proprement en conservant ce qu'on trouve.

async function fetchJson(url, opts = {}) {
  const res = await fetch(url, { ...opts, headers: { 'Accept': 'application/json', ...(opts.headers || {}) } });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const err = new Error(`HTTP ${res.status} ${res.statusText}: ${text}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

function pickCvssScore(cna) {
  const metrics = cna?.metrics || [];
  let scores = [];
  for (const m of metrics) {
    if (m?.cvssV4) scores.push(m.cvssV4?.baseScore);
    if (m?.cvssV3_1) scores.push(m.cvssV3_1?.baseScore);
    if (m?.cvssV3) scores.push(m.cvssV3?.baseScore);
  }
  scores = scores.filter((s) => typeof s === 'number');
  return scores.length ? Math.max(...scores) : null;
}

function sanitizeUrl(u) {
  const s = String(u)
    .trim()
    .replace(/[`"'<>]/g, '') // enlève backticks, guillemets, chevrons
    .replace(/\s+/g, '');    // enlève espaces parasites
  try {
    const parsed = new URL(s);
    return parsed.toString();
  } catch {
    return null;
  }
}

function stripHtml(html) {
  if (!html) return null;
  const text = String(html).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  return text || null;
}

function mapCveOrgToResource(cveId, data) {
  const cna = data?.containers?.cna || {};
  const meta = data?.cveMetadata || {};

  const titleRaw = cna.title || null;
  const title = stripHtml(titleRaw);

  const descRaw =
    Array.isArray(cna.descriptions) && cna.descriptions.length ? cna.descriptions[0].value : null;
  const description = stripHtml(descRaw);
  const description_html = descRaw || null;

  const referencesRaw = Array.isArray(cna.references) ? cna.references.map((r) => r.url || r.name || r) : [];
  const references = Array.from(
    new Set(
      referencesRaw
        .map(sanitizeUrl)
        .filter((u) => !!u)
    )
  );

  const affected_products = Array.isArray(cna.affected)
    ? cna.affected
        .map((a) => [a.vendor, a.product, a.versions?.map((v) => v.version).filter(Boolean).join('/')].filter(Boolean).join(' '))
        .filter(Boolean)
    : [];

  const cvss_score = pickCvssScore(cna);

  const severity =
    Array.isArray(cna.metrics) && cna.metrics.length
      ? (cna.metrics[0]?.cvssV3_1?.baseSeverity ||
         cna.metrics[0]?.cvssV3?.baseSeverity ||
         cna.metrics[0]?.cvssV4?.baseSeverity || null)?.toLowerCase()
      : null;

  const published_at = meta?.datePublished || null;
  const last_modified = meta?.dateUpdated || meta?.dateReserved || null;

  const recommendation =
    cna?.solutions?.[0]?.value
      ? stripHtml(cna.solutions[0].value)
      : `Consulter les avis du fournisseur et appliquer les correctifs disponibles.`;

  return {
    cve_id: String(cveId).toUpperCase(),
    title,
    description,
    description_html,
    severity,
    cvss_score,
    affected_products,
    references,
    recommendation,
    published_at,
    last_modified
  };
}

async function getCveFromCveOrg(cveId) {
  const id = String(cveId).toUpperCase();
  const url = `https://cveawg.mitre.org/api/cve/${id}`;
  const json = await fetchJson(url);
  if (!json?.cveMetadata?.cveId) {
    const err = new Error('CVE not found');
    err.status = 404;
    throw err;
  }
  return mapCveOrgToResource(id, json);
}

module.exports = {
  getCveFromCveOrg
};