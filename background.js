const warningPage = chrome.runtime.getURL("warningPage.html");

//const phishingSigns = new Set([
//]);


function isNotHTTPS(protocol) {

  if(protocol !== "https:") {
    return true;
  }

  return false;
}

function hasIPAddress(url) {

    // IPv4 regex
    const ipv4 =
      /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

    // IPv6 regex
    const ipv6 =
      /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(([0-9a-fA-F]{1,4}:){1,7}:)|(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})|(([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2})|(([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3})|(([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4})|(([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5})|([0-9a-fA-F]{1,4}:)((:[0-9a-fA-F]{1,4}){1,6})|(:)((:[0-9a-fA-F]{1,4}){1,7}|:))$/;

    // Checks if URL matches the IPv4 regex
    if (url.match(ipv4)) {
      return true;
    }

    // Checks if URL matches the IPv6 regex
    if (url.match(ipv6)) {
      return true;
    }

    return false;
}

function urlLength(url) {
  return url.length > 52;
}

function multipleSubDomains(url) {

  // -2 because we don't count the top level domain and the main domain
  let subdomains = url.split(".").length - 2;

  if (subdomains > 2) {
    return true;
  }

  return false;

}

function letterNumberSubstitution(url) {

    // Remove dots (so subdomains don't interfere)
    const compactURL = url.split(".");

    for (let i = 0; i < compactURL.length; i++) {
      if (!/[a-z]/.test(compactURL[i]) || !/\d/.test(compactURL[i])) {
        continue;
      }
      else if (/[a-z]+\d+[a-z]+/.test(compactURL[i])) {
        return true;
      }
    }

    return false;

}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {

  // Will change to true if any phishing is detected 
  let phishing = false;

  let phishingSigns = new Set();

  // Only check when loading a new URL
  if (!changeInfo.url) return;

  // Checks if the URL is the extension itself or a new page, which should be ignored
  if (changeInfo.url.startsWith("chrome-extension://") || changeInfo.url.startsWith("chrome://extensions/") || changeInfo.url.startsWith("about:blank") || changeInfo.url.startsWith("chrome://newtab/")) return;
  
  let url = new URL(changeInfo.url);

  // Checks if the URL is not HTTPS, which is a common sign of phishing
  if (isNotHTTPS(url.protocol)) {
    phishingSigns.add("NOT_HTTPS");
    phishing = true;
  }

  // Checks if the URL uses an IP address instead of a domain name, which is a common sign of phishing
  if (hasIPAddress(url.host)) {
    phishingSigns.add("IP_ADDRESS");
    phishing = true;
  }

  // Checks if the URL is excessively long, which can be a sign of phishing
  if (urlLength(url.href)) {
    phishingSigns.add("LONG_URL");
    phishing = true;
  }

  // Checks if the URL has multiple subdomains, which can be a sign of phishing
  if (multipleSubDomains(url.host)) {
    phishingSigns.add("MULTIPLE_SUBDOMAINS");
    phishing = true;
  }

  // Checks for some common letter-number substitutions, which can be a sign of phishing
  if (letterNumberSubstitution(url.host)) {
    phishingSigns.add("LETTER_SUBSTITUTION_WITH_NUMBERS");
    phishing = true;
  }

  console.log("Current phishing signs:", Array.from(phishingSigns));

  console.log("Checking URL:", url);

  // If phishing is detected, redirect to the warning page
  if (phishing) {
    const warningUrl =
      warningPage +
      "?url=" +
      encodeURIComponent(url.href) +
      "&signs=" +
      encodeURIComponent(JSON.stringify(Array.from(phishingSigns)));

    chrome.tabs.update(tabId, { url: warningUrl });
  }

}); 