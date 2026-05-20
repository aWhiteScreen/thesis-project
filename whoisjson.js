export async function checkWhois(domain) {
  try {
    const response = await fetch(
      "https://whoisjson.com/api/v1/whois?" +
        new URLSearchParams({ domain }),
      {
        method: "GET",
        headers: {
          Authorization: "Token=47dace066e2ac243fd07c208c3d25c9311f2a74fe01f3fcd31c35fd03bf9840c"
        }
      }
    );

    if (!response.ok) {
      console.warn("WHOIS API error:", response.status);
      return null;
    }

    const data = await response.json();
    return data;

  } catch (error) {
    console.error("WHOIS error:", error);
    return null;
  }
}

export async function checkSSL(domain) {
  try {
    const response = await fetch(
      "https://whoisjson.com/api/v1/ssl-cert-check?" +
        new URLSearchParams({ domain }),
      {
        method: "GET",
        headers: {
          Authorization: "Token=47dace066e2ac243fd07c208c3d25c9311f2a74fe01f3fcd31c35fd03bf9840c"
        }
      }
    );

    if (!response.ok) {
      console.warn("SSL API error:", response.status);
      return null;
    }

    const data = await response.json();
    return data;

  } catch (error) {
    console.error("SSL error:", error);
    return null;
  }
}