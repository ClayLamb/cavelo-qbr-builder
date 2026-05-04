// brand-save.js
// Saves a single global brand profile in-memory.
// NOTE: In-memory only — resets on function cold start. For persistence,
// swap brandStore for a Netlify Blob or KV store.
//
// Uses the same global._qbrBrandStore as brand-load.js so save/load can
// see each other's writes (Netlify spawns each function in its own
// module scope; module-local consts don't share).

const busboy = require("busboy");

if (!global._qbrBrandStore) global._qbrBrandStore = {};
const brandStore = global._qbrBrandStore;
const BRAND_KEY = "default";

function parseBrandFormData(event) {
  return new Promise((resolve, reject) => {
    const profile = {};
    const bb = busboy({ headers: { "content-type": event.headers["content-type"] } });

    bb.on("field", (name, val) => { profile[name] = val; });
    bb.on("file", (name, stream, info) => {
      if (name === "logo") {
        const chunks = [];
        stream.on("data", d => chunks.push(d));
        stream.on("end", () => {
          const buf = Buffer.concat(chunks);
          profile.logoData = `data:${info.mimeType};base64,${buf.toString("base64")}`;
        });
      } else {
        stream.resume();
      }
    });
    bb.on("close", () => resolve(profile));
    bb.on("error", reject);

    const body = Buffer.from(event.body, event.isBase64Encoded ? "base64" : "utf8");
    bb.write(body);
    bb.end();
  });
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method not allowed" };

  try {
    const profile = await parseBrandFormData(event);
    const { mspName, mspUrl, primaryColor, contactName, contactEmail, contactPhone, logoData } = profile;

    brandStore[BRAND_KEY] = { mspName, mspUrl, primaryColor, contactName, contactEmail, contactPhone, logoData };

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ success: true, profile: brandStore[BRAND_KEY] }),
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ success: false, error: e.message }) };
  }
};
