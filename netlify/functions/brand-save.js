// brand-save.js
// Saves MSP brand profile in-memory (keyed by access code)
// NOTE: In-memory only — resets on function cold start.
// For persistence, swap brandStore for a Netlify Blob or KV store.

const busboy = require("busboy");

const brandStore = {}; // { [code]: profileObject }

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
    const { code, mspName, mspUrl, primaryColor, contactName, contactEmail, contactPhone, logoData } = profile;

    if (!code || code !== process.env.SITE_PASSWORD) {
      return { statusCode: 401, body: JSON.stringify({ success: false, error: "Unauthorized" }) };
    }

    brandStore[code] = { mspName, mspUrl, primaryColor, contactName, contactEmail, contactPhone, logoData };

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ success: true, profile: brandStore[code] }),
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ success: false, error: e.message }) };
  }
};
