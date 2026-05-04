exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method not allowed" };
  try {
    const { code } = JSON.parse(event.body);
    const valid = code === process.env.SITE_PASSWORD;
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ success: valid }),
    };
  } catch {
    return { statusCode: 400, body: JSON.stringify({ success: false }) };
  }
};
