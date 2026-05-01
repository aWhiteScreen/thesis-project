export async function checkWhois(domain) {
  try {
    const response = await fetch(
      "https://whoisjson.com/api/v1/whois?" +
        new URLSearchParams({ domain }),
      {
        method: "GET",
        headers: {
          Authorization: "Token=869ac83fe2eb4694780e5d0f214981500a476504e20029c25078ed31602de322"
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
          Authorization: "Token=869ac83fe2eb4694780e5d0f214981500a476504e20029c25078ed31602de322"
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