export function registeredDomainMismatch(hostname, websiteData) {
  const urlDomain = hostname.replace(/^www\./, "").toLowerCase();

  const whoisName = websiteData?.name?.replace(/^www\./, "").toLowerCase();
  const whoisIdnName = websiteData?.idnName?.replace(/^www\./, "").toLowerCase();

  if (!whoisName && !whoisIdnName) {
    return false;
  }

  const matchesWhoisName =
    whoisName &&
    (urlDomain === whoisName || urlDomain.endsWith("." + whoisName));

  const matchesIdnName =
    whoisIdnName &&
    (urlDomain === whoisIdnName || urlDomain.endsWith("." + whoisIdnName));

  return !matchesWhoisName && !matchesIdnName;
}