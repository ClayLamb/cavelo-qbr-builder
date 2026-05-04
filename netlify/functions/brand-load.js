// brand-load.js
// Loads a saved brand profile from in-memory store

// Share the same store instance (works within the same function instance)
// For persistence across cold starts, swap for Netlify Blobs
const { brandStore } = (() => {
  if (!global._qbrBrandStore) global._qbrBrandStore = {};
  return { brandStore: global._qbrBrandStore };
})();

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method not allowed" };
  try {
    const { code } = JSON.parse(event.body);
    if (!code || code !== process.env.SITE_PASSWORD) {
      return { statusCode: 401, body: JSON.stringify({ success: false }) };
    }
    const profile = brandStore[code] || null;
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ success: true, profile }),
    };
  } catch {
    return { statusCode: 400, body: JSON.stringify({ success: false }) };
  }
};
