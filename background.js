import { checkWhois } from "./whoisjson.js";


const warningPage = chrome.runtime.getURL("warningPage.html");

var oldURL = '';
//const phishingSigns = new Set([
//]);


function isNotHTTPS(protocol) {

  if(protocol !== "https:") {
    return true;
  } else return false;
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
  } else return false;

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

function suspiciousTLD(url) {
    const tlds = [
      "win",
      "help",
      "bond",
      "cfd",
      "finance",
      "world",
      "top",
      "icu",
      "support",
      "vip",
      "cyou",
      "pro",
      "sbs",
      "monster",
      "mom",
      "click",
      "quest",
      "buzz",
      "ink",
      "fyi"
    ];

    const urlTLD = url.split(".").pop();

    if (tlds.includes(urlTLD)) {
      return true;
    } else {
      return false;
    }

}

function tooManyHyphens(url) {

    let hyphenCount = 0; 

    for(let i = 0; i < url.length; i++) {
      if (url[i] == "-") {
        hyphenCount++;
      }
    }

    if (hyphenCount >= 2) {
      return true;
    } else return false;
}

function tooManySlashes(url) {

    let slashCount = 0; 

    for(let i = 0; i < url.length; i++) {
      if (url[i] == "/") {
        slashCount++;
      }
    }

    if (slashCount >= 5) {
      return true;
    } else return false;
}

function oldDomain(age) {
  if (age < 6) {
    return true;
  } else return false;
}


chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {

  // Will change to true if any phishing is detected 
  let phishing = false;

  let phishingSigns = new Set();

  // Only check when loading a new URL
  if (!changeInfo.url) return;

  // Checks if the URL is the extension itself or a new page, which should be ignored
  if (changeInfo.url.startsWith("chrome-extension://") || changeInfo.url.startsWith("chrome://extensions/") || changeInfo.url.startsWith("about:blank") || changeInfo.url.startsWith("chrome://newtab/")) return;
  
  let url = new URL(changeInfo.url);

  if (url.hostname == "www.google.com" || url.hostname == "workspace.google.com" || url.hostname == "accounts.google.com") {
    return;
  }


  // If user decided to proceed to the phishing website, do not check for phishing again
  if (url.href == oldURL) {
    return;
  }

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

  // Checks if the URL has a suspicious top-level domain, which can be a sign of phishing
  if (suspiciousTLD(url.host)) {
    phishingSigns.add("SUSPICIOUS_TLD");
    phishing = true;
  }

  // Check if the URL has more hyphens than is expected, since it can be a sign of phishing
  if (tooManyHyphens(url.host)) {
    phishingSigns.add("TOO_MANY_HYPHENS");
    phishing = true;
  }

  // Check if the URL has more hyphens than is expected, since it can be a sign of phishing
  if (tooManySlashes(url.href)) {
    phishingSigns.add("TOO_MANY_SLASHES");
    phishing = true;
  }

  const websiteData = await checkWhois(url.hostname);
  console.log("WHOIS data:", websiteData);
  console.log("WHOIS months:", websiteData.age.months);

  if(!websiteData) {
    phishingSigns.add("NO_RECORD");
    phishing = true;
  }

  // Checks if the domain is younger than 6 months, which can be a sign of phishing
  if (oldDomain(websiteData.age.months)) {
    phishingSigns.add("OLD_DOMAIN");
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


// Listener for checking if user proceeded to the phishing website anyway
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ALLOW_URL") {
    oldURL = message.url;
    sendResponse({ ok: true });
  }
});