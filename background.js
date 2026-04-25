const warningPage = chrome.runtime.getURL("warning.html");

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

  console.log("Current phishing signs:", Array.from(phishingSigns));

  console.log("Checking URL:", url);

  // If phishing is detected, redirect to the warning page
  if (phishing) {
    chrome.tabs.update(tabId, { url: warningPage });
    console.log("Current phishing signs:", Array.from(phishingSigns));
}

}); 