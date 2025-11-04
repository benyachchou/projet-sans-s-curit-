// Service d'intégration NVD (API v2): https://services.nvd.nist.gov/rest/json/cves/2.0
// Node >=18: utilise fetch natif. Supporte clé API via env NVD_API_KEY.

const API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchJson(url) {
  const headers = { Accept: 'application/json' };
  const apiKey = process.env.NVD_API_KEY;
  if (apiKey) headers['apiKey'] = apiKey;
  const res = await fetch(url, { headers });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const err = new Error(`HTTP ${res.status} ${res.statusText}: ${text}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

function sanitizeUrl(u) {
  const s = String(u).trim().replace(/[`"'<>]/g, '').replace(/\s+/g, '');
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

function pickCvssScore(metrics) {
  const m = metrics || {};
  const v31 = m.cvssMetricV31 || [];
  const v3 = m.cvssMetricV3 || [];
  const v2 = m.cvssMetricV2 || [];
  const scores = [];
  for (const it of v31) scores.push(it?.cvssData?.baseScore);
  for (const it of v3) scores.push(it?.cvssData?.baseScore);
  for (const it of v2) scores.push(it?.cvssData?.baseScore);
  const num = scores.filter((s) => typeof s === 'number');
  return num.length ? Math.max(...num) : null;
}

function pickSeverity(metrics) {
  const m = metrics || {};
  const v31 = m.cvssMetricV31 || [];
  const v3 = m.cvssMetricV3 || [];
  const v2 = m.cvssMetricV2 || [];
  const sev =
    v31[0]?.cvssData?.baseSeverity ||
    v3[0]?.cvssData?.baseSeverity ||
    v2[0]?.baseSeverity ||
    null;
  return sev ? String(sev).toLowerCase() : null;
}

function parseCpeUri(uri) {
  // cpe:2.3:a:vendor:product:version:update:edition:language:...
  try {
    const parts = String(uri).split(':');
    if (parts.length < 6) return null;
    const vendor = parts[3] || '';
    const product = parts[4] || '';
    const version = parts[5] || '';
    const out = [vendor, product, version].filter(Boolean).join(' ');
    return out || null;
  } catch {
    return null;
  }
}

function extractAffectedProducts(configurations) {
  const out = new Set();
  try {
    const nodes = configurations?.nodes || [];
    for (const n of nodes) {
      const matches = n?.cpeMatch || [];
      for (const m of matches) {
        const name = parseCpeUri(m?.criteria || m?.cpe23Uri);
        if (name) out.add(name);
      }
      const children = n?.children || [];
      for (const c of children) {
        const cm = c?.cpeMatch || [];
        for (const m of cm) {
          const name = parseCpeUri(m?.criteria || m?.cpe23Uri);
          if (name) out.add(name);
        }
      }
    }
  } catch {}
  return Array.from(out);
}

function mapNvdCveToResource(vuln) {
  const cve = vuln?.cve || {};
  const id = cve?.id || '';
  const descriptions = cve?.descriptions || [];
  const descEn = descriptions.find((d) => String(d.lang).toLowerCase() === 'en') || descriptions[0] || {};
  const description_html = descEn?.value || null;
  const description = stripHtml(description_html);

  const references = Array.isArray(cve?.references)
    ? Array.from(
        new Set(
          cve.references
            .map((r) => sanitizeUrl(r?.url || r))
            .filter(Boolean)
        )
      )
    : [];

  const affected_products = extractAffectedProducts(cve?.configurations);

  const cvss_score = pickCvssScore(cve?.metrics);
  const severity = pickSeverity(cve?.metrics);

  const published_at = cve?.published || null;
  const last_modified = cve?.lastModified || null;

  // NVD ne fournit pas de recommandations directes → générique
  const recommendation = 'Consulter les avis du fournisseur et appliquer les correctifs disponibles.';

  // Titre: NVD n’a pas de titre distinct → derive du début de description
  const title = description ? description.slice(0, 120) : id;

  return {
    cve_id: String(id).toUpperCase(),
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

function ensureUtcIso(s) {
  const str = String(s || '').trim();
  if (!str) return null;
  // Si la date n'a pas de timezone (Z ou offset), ajoute 'Z' (UTC)
  return /Z$|[+\-]\d{2}:\d{2}$/.test(str) ? str : str + 'Z';
}

async function getNvdById(cveId) {
  const id = String(cveId).toUpperCase();
  const url = `${API_BASE}?cveId=${encodeURIComponent(id)}`;
  const json = await fetchJson(url);
  // NVD v2: la liste est sous 'vulnerabilities'
  const vulns = Array.isArray(json?.vulnerabilities) ? json.vulnerabilities : [];
  if (!vulns.length) {
    const err = new Error('CVE not found in NVD');
    err.status = 404;
    throw err;
  }
  // Chaque élément a la forme { cve: { ... } }
  return mapNvdCveToResource(vulns[0]);
}

async function getNvdRange({ pubStartDate, pubEndDate, resultsPerPage = 2000, delayMs = 1500 }) {
  // Respect des limites NVD: ajoute un petit délai entre les pages
  const paramsBase = new URLSearchParams();
  const startIso = ensureUtcIso(pubStartDate);
  const endIso = ensureUtcIso(pubEndDate);
  paramsBase.set('pubStartDate', startIso);
  paramsBase.set('pubEndDate', endIso);
  paramsBase.set('resultsPerPage', String(Math.min(Math.max(resultsPerPage, 1), 2000)));

  let startIndex = 0;
  const items = [];
  while (true) {
    const params = new URLSearchParams(paramsBase);
    params.set('startIndex', String(startIndex));
    const url = `${API_BASE}?${params.toString()}`;
    const json = await fetchJson(url);
    // NVD v2: 'vulnerabilities' + 'totalResults'
    const vulns = Array.isArray(json?.vulnerabilities) ? json.vulnerabilities : [];
    if (!vulns.length) break;

    for (const v of vulns) items.push(mapNvdCveToResource(v));

    const total = Number(json?.totalResults || 0);
    startIndex += vulns.length;
    if (startIndex >= total) break;
    await sleep(delayMs);
  }
  return items;
}

module.exports = {
  getNvdById,
  getNvdRange
};