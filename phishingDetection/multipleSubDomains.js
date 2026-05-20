export async function multipleSubDomains(url) {
  const parts = url.split(".");

  // If the first part is "www", ignore both "www" and the TLD (-2),
  // Otherwise, ignore only the TLD (-1).
  const subdomains =
    parts[0].toLowerCase() === "www"
      ? parts.length - 2
      : parts.length - 1;


  if (subdomains > 2) {
    return true;
  } else {
    return false;
  }
}