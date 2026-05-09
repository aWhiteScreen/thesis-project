export async function getWhitelist() {
  const data = await chrome.storage.local.get("whitelist");
  return data.whitelist || [];
}

export async function isWhitelisted(hostname) {
  const whitelist = await getWhitelist();
  const cleanHost = hostname.replace(/^www\./, "").toLowerCase();

  return whitelist.some((site) => {
    return cleanHost === site || cleanHost.endsWith("." + site);
  });
}