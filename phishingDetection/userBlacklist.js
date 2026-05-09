export async function getBlacklist() {
  const data = await chrome.storage.local.get("blacklist");
  return data.blacklist || [];
}

export async function isBlacklisted(hostname) {
  const blacklist = await getBlacklist();
  const cleanHost = hostname.replace(/^www\./, "").toLowerCase();

  return blacklist.some((site) => {
    return cleanHost === site || cleanHost.endsWith("." + site);
  });
}