const GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyDjPzkzxAw_X3pWlxNo8A7X_ZC6EchIaVA";

export async function checkGoogleSafeBrowsing(urlToCheck) {
  const endpoint =
    "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
    GOOGLE_SAFE_BROWSING_API_KEY;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      client: {
        clientId: "phishing-detector",
        clientVersion: "1.0"
      },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING"
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [
          {
            url: urlToCheck
          }
        ]
      }
    })
  });

  const data = await response.json();

  return data.matches && data.matches.length > 0;
}