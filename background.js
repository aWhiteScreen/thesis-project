import { checkWhois } from "./whoisjson.js";
import { checkSSL } from "./whoisjson.js";
import { checkGoogleSafeBrowsing } from "./googleSafeBrowsingApi.js";

const warningPage = chrome.runtime.getURL("html/warningPage.html");

const tabStates = new Map();

const rawURLs = new Map();

const SAFE_ICONS = {
  "16": "icons/safety16x16.png",
  "32": "icons/safety32x32.png",
  "48": "icons/safety48x48.png",
  "64": "icons/safety64x64.png",
  "128": "icons/safety128x128.png"
};

const WARNING_ICONS = {
  "16": "icons/warning16x16.png",
  "32": "icons/warning32x32.png",
  "48": "icons/warning48x48.png",
  "64": "icons/warning64x64.png",
  "128": "icons/warning128x128.png"
};

var oldURL = '';

function setTabState(tabId, phishing, signs = []) {
  tabStates.set(tabId, {
    phishing,
    signs
  });

  chrome.action.setIcon({
    tabId,
    path: phishing ? WARNING_ICONS : SAFE_ICONS
  });
}

async function getWhitelist() {
  const data = await chrome.storage.local.get("whitelist");
  return data.whitelist || [];
}

function normalizeHostname(input) {
  try {
    if (!input.startsWith("http://") && !input.startsWith("https://")) {
      input = "https://" + input;
    }

    return new URL(input).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return null;
  }
}

async function isWhitelisted(hostname) {
  const whitelist = await getWhitelist();
  const cleanHost = hostname.replace(/^www\./, "").toLowerCase();

  return whitelist.some((site) => {
    return cleanHost === site || cleanHost.endsWith("." + site);
  });
}

async function getBlacklist() {
  const data = await chrome.storage.local.get("blacklist");
  return data.blacklist || [];
}

async function isBlacklisted(hostname) {
  const blacklist = await getBlacklist();
  const cleanHost = hostname.replace(/^www\./, "").toLowerCase();

  return blacklist.some((site) => {
    return cleanHost === site || cleanHost.endsWith("." + site);
  });
}

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
  return url.length > 75;
}

function multipleSubDomains(url) {
  const parts = url.split(".");

  // If the first part is "www", ignore both "www" and the TLD,
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

function youngDomain(age) {
  if (age < 6) {
    return true;
  } else return false;
}

function selfSignedCert(subject, issuer) {
  if (JSON.stringify(subject) === JSON.stringify(issuer)) {
    return true;
  } else return false;
}

function registeredDomainMismatch(hostname, websiteData) {
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

function atSign(url) {
  if (url.includes("@")) {
    return true;
  } else return false;
}


chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!details.url.startsWith("http://") && !details.url.startsWith("https://")) return;
  if (!details.url.includes("@")) return;

  rawURLs.set(details.tabId, details.url);
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {

  // Will change to true if any phishing is detected 
  let phishing = false;

  // List of current phishingSigns
  let phishingSigns = new Set();

  // Only check when loading a new URL
  if (!changeInfo.url) return;

  // Checks if the URL is the extension itself or a new page, which should be ignored
  if (changeInfo.url.startsWith("chrome-extension://") || changeInfo.url.startsWith("chrome://extensions/") || changeInfo.url.startsWith("about:blank") || changeInfo.url.startsWith("chrome://newtab/")) return;
  
  let url = new URL(changeInfo.url);

  const rawURL = rawURLs.get(tabId) || changeInfo.url;

  // Check if the URL is whitelisted
  if (await isWhitelisted(url.hostname)) {
    setTabState(tabId, false, []);
    return;
  }

  if (url.hostname == "www.google.com" || url.hostname == "workspace.google.com" || url.hostname == "accounts.google.com" || url.hostname == "mail.google.com") {
    return;
  }

  // If user decided to proceed to the phishing website, do not check for phishing again, also keeps the warning symbol
  if (url.hostname == oldURL) {
    setTabState(tabId, true, Array.from(phishingSigns));
    return;
  }

  // Check if the URL is blacklisted by the user
  if (await isBlacklisted(url.hostname)) {
    phishingSigns.add("BLACKLISTED_BY_USER");
    phishing = true;
  }

  let googleData = await checkGoogleSafeBrowsing(url.href);
  console.log("google data", googleData);

  // Checks if the URL is blacklisted by Google's safe browsing API
  if (await checkGoogleSafeBrowsing(url.href)) {
    phishingSigns.add("BLACKLISTED_BY_GOOGLE");
    phishing = true;
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

  // Check if domain has no WHOIS record, which can be a sign of phishing
  if(!websiteData) {
    phishingSigns.add("NO_RECORD");
    phishing = true;
  }

  // Checks if the domain is younger than 6 months, which can be a sign of phishing
  if (websiteData?.age?.months !== undefined) {
    if (youngDomain(websiteData.age.months)) {
      phishingSigns.add("YOUNG_DOMAIN");
      phishing = true;
    }
  }

  const sslData = await checkSSL(url.hostname);
 
  // Check is the TLS/SSL certificate is self-signed, which can be a sign of phishing
  if (sslData?.details?.subject && sslData?.issuer) {
    if (selfSignedCert(sslData.details.subject, sslData.issuer)) {
      phishingSigns.add("SELF_SIGNED_SSL");
      phishing = true;
    }
  }

  // Checks if URL domain does not match with the registered domain, which can be a sign of phishing
  if (registeredDomainMismatch(url.hostname, websiteData)) {
    phishingSigns.add("DOMAIN_MISMATCH");
    phishing = true;
  }

  if (atSign(rawURL)) {
    phishingSigns.add("AT_SIGN");
    phishing = true;
  }

  console.log("URL", url);

  // If phishing is detected, redirect to the warning page
  if (phishing) {
    setTabState(tabId, true, Array.from(phishingSigns));


    const warningUrl =
      warningPage +
      "?url=" +
      encodeURIComponent(rawURL) +
      "&signs=" +
      encodeURIComponent(JSON.stringify(Array.from(phishingSigns)));

    chrome.tabs.update(tabId, { url: warningUrl });
  } else {
    setTabState(tabId, false, []); 
  }

});


// Listener for checking if user proceeded to the phishing website anyway
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ALLOW_URL") {
    oldURL = message.url;
    sendResponse({ ok: true });
  }

  if (message.type === "GET_TAB_STATE") {
    const state = tabStates.get(message.tabId) || {
      phishing: false,
      signs: []
    };

    sendResponse(state);
    return true;
  }

  if (message.type === "ADD_TO_WHITELIST") {
    const hostname = normalizeHostname(message.url);

    if (!hostname) {
      sendResponse({ ok: false, error: "Invalid URL" });
      return true;
    }

    chrome.storage.local.get("whitelist").then((data) => {
      const whitelist = data.whitelist || [];

      if (!whitelist.includes(hostname)) {
        whitelist.push(hostname);
      }

      chrome.storage.local.set({ whitelist }).then(() => {
        sendResponse({ ok: true, whitelist });
      });
    });

    return true;
  }

  if (message.type === "GET_WHITELIST") {
    chrome.storage.local.get("whitelist").then((data) => {
      sendResponse({ whitelist: data.whitelist || [] });
    });

    return true;
  }

  if (message.type === "REMOVE_FROM_WHITELIST") {
    const hostname = normalizeHostname(message.url);

    chrome.storage.local.get("whitelist").then((data) => {
      const whitelist = data.whitelist || [];
      const updatedWhitelist = whitelist.filter((site) => site !== hostname);

      chrome.storage.local.set({ whitelist: updatedWhitelist }).then(() => {
        sendResponse({ ok: true, whitelist: updatedWhitelist });
      });
    });

    return true;
  }

  if (message.type === "ADD_TO_BLACKLIST") {
    const hostname = normalizeHostname(message.url);

    if (!hostname) {
      sendResponse({ ok: false, error: "Invalid URL" });
      return true;
    }

    chrome.storage.local.get("blacklist").then((data) => {
      const blacklist = data.blacklist || [];

      if (!blacklist.includes(hostname)) {
        blacklist.push(hostname);
      }

      chrome.storage.local.set({ blacklist }).then(() => {
        sendResponse({ ok: true, blacklist });
      });
    });

    return true;
  }

  if (message.type === "GET_BLACKLIST") {
    chrome.storage.local.get("blacklist").then((data) => {
      sendResponse({ blacklist: data.blacklist || [] });
    });

    return true;
  }

  if (message.type === "REMOVE_FROM_BLACKLIST") {
    const hostname = normalizeHostname(message.url);

    chrome.storage.local.get("blacklist").then((data) => {
      const blacklist = data.blacklist || [];
      const updatedBlacklist = blacklist.filter((site) => site !== hostname);

      chrome.storage.local.set({ blacklist: updatedBlacklist }).then(() => {
        sendResponse({ ok: true, blacklist: updatedBlacklist });
      });
    });

    return true;
  }

});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
});