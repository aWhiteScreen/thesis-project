import { checkWhois } from "./whoisjson.js";
import { checkSSL } from "./whoisjson.js";
import { checkGoogleSafeBrowsing } from "./googleSafeBrowsingApi.js";
import { hasIPAddress } from "./phishingDetection/hasIPAddress.js";
import { isNotHTTPS } from "./phishingDetection/isNotHTTPS.js";
import { tooManyHyphens } from "./phishingDetection/tooManyHyphens.js";
import { tooManySlashes } from "./phishingDetection/tooManySlashes.js";
import { letterNumberSubstitution } from "./phishingDetection/letterNumberSubstitution.js";
import { suspiciousTLD } from "./phishingDetection/suspiciousTLD.js";
import { urlLength } from "./phishingDetection/urlLength.js"
import { youngDomain } from "./phishingDetection/youngDomain.js";
import { multipleSubDomains } from "./phishingDetection/multipleSubDomains.js";
import { registeredDomainMismatch } from "./phishingDetection/registeredDomainMismatch.js";
import { selfSignedCert } from "./phishingDetection/selfSignedCert.js";
import { atSign } from "./phishingDetection/atSign.js";
import { getBlacklist, isBlacklisted } from "./phishingDetection/userBlacklist.js";
import { getWhitelist, isWhitelisted } from "./phishingDetection/userWhitelist.js";
import { normalizeHostname } from "./util/normalizeHostname.js";
import { shortenedURL} from "./phishingDetection/shortenedURL.js";


const warningPage = chrome.runtime.getURL("html/warningPage.html");

const tabStates = new Map();

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

// Meant for URLs where the warning was ignored 
const allowedHosts = new Map();

async function setTabState(tabId, phishing, signs = []) {
  const state = { phishing, signs };

  tabStates.set(tabId, state);

  await chrome.storage.session.set({
    ["tabState_" + tabId]: state
  });

  chrome.action.setIcon({
    tabId,
    path: phishing ? WARNING_ICONS : SAFE_ICONS
  });
}

// Retains the entire URL if @ is used
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!details.url.startsWith("http://") && !details.url.startsWith("https://")) return;

  // Check if @ sign is used to try and redirect to another link
  if (atSign(details.url)) {
    setTabState(details.tabId, true, []);

    const warningUrl =
      warningPage +
      "?url=" +
      encodeURIComponent(details.url) +
      "&signs=" +
      encodeURIComponent(JSON.stringify(["AT_SIGN"]));
    chrome.tabs.update(details.tabId, { url: warningUrl });
    
    return;

  }

  // Check if shorteners are used to redirect to another link
  let beforeNavURL = new URL(details.url);
  if (shortenedURL(beforeNavURL.hostname)) {
    setTabState(details.tabId, true, []);

    const warningUrl =
      warningPage +
      "?url=" +
      encodeURIComponent(details.url) +
      "&signs=" +
      encodeURIComponent(JSON.stringify(["SHORTENED_URL"]));
    chrome.tabs.update(details.tabId, { url: warningUrl });

    return;
  }

});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {

  // Will change to true if any phishing is detected 
  let phishing = false;

  // List of current phishingSigns
  let phishingSigns = new Set();

  // Only check when loading a new URL
  if (!changeInfo.url) return;


  // If users goes back to the warning page after proceeding to the phishing website
  if (changeInfo.url.startsWith(warningPage)) {
    const warningUrl = new URL(changeInfo.url);
    const signs = JSON.parse(warningUrl.searchParams.get("signs") || "[]");

    setTabState(tabId, true, signs);
    return;
  }

  // Security state should change to safe in an empty tab
  if (changeInfo.url.startsWith("about:blank")) {
    setTabState(tabId, false, []);
    return;
  }

  // Checks if the URL is the extension itself or a new page, which should be ignored
  if (changeInfo.url.startsWith("chrome-extension://") || changeInfo.url.startsWith("chrome://extensions/") || changeInfo.url.startsWith("chrome://newtab/")) return;
  
  let url = new URL(changeInfo.url);

  // Check if the URL is whitelisted
  if (await isWhitelisted(url.hostname)) {
    setTabState(tabId, false, []);
    return;
  }

  if (url.hostname == "www.google.com" || url.hostname == "workspace.google.com" || url.hostname == "accounts.google.com" || url.hostname == "mail.google.com") {
    return;
  }

  // If user decided to proceed to the phishing website, do not check for phishing again, also keeps the warning symbol
  if (allowedHosts.get(tabId) === url.hostname) {
    setTabState(tabId, true, Array.from(phishingSigns));
    return;
  }

  // Check if the URL is blacklisted by the user
  if (await isBlacklisted(url.hostname)) {
    phishingSigns.add("BLACKLISTED_BY_USER");
    phishing = true;
  }

  let googleData = await checkGoogleSafeBrowsing(url.href);

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
  if (hasIPAddress(url.hostname)) {
    phishingSigns.add("IP_ADDRESS");
    phishing = true;
  }

  // Checks if the URL has multiple subdomains, which can be a sign of phishing
  if (multipleSubDomains(url.hostname)) {
    phishingSigns.add("MULTIPLE_SUBDOMAINS");
    phishing = true;
  }

  // Checks for some common letter-number substitutions, which can be a sign of phishing
  if (letterNumberSubstitution(url.hostname)) {
    phishingSigns.add("LETTER_SUBSTITUTION_WITH_NUMBERS");
    phishing = true;
  }

  // Checks if the URL has a suspicious top-level domain, which can be a sign of phishing
  if (suspiciousTLD(url.hostname)) {
    phishingSigns.add("SUSPICIOUS_TLD");
    phishing = true;
  }

  // Check if the URL has more hyphens than is expected, since it can be a sign of phishing
  if (tooManyHyphens(url.hostname)) {
    phishingSigns.add("TOO_MANY_HYPHENS");
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

  // If hostname is fine then the length or slashes probably don't matter
  if(!phishing) {
    return;
  }

  // Check if the URL has more hyphens than is expected, since it can be a sign of phishing
  if (tooManySlashes(url.href)) {
    phishingSigns.add("TOO_MANY_SLASHES");
    phishing = true;
  }

  // Checks if the URL is excessively long, which can be a sign of phishing
  if (urlLength(url.href)) {
    phishingSigns.add("LONG_URL");
    phishing = true;
  }

  console.log(phishingSigns);
  // If phishing is detected, redirect to the warning page
  if (phishing) {
    setTabState(tabId, true, Array.from(phishingSigns));

    const warningUrl =
      warningPage +
      "?url=" +
      encodeURIComponent(url) +
      "&signs=" +
      encodeURIComponent(JSON.stringify(Array.from(phishingSigns)));

    chrome.tabs.update(tabId, { url: warningUrl });
  } else {
    setTabState(tabId, false, []); 
  }

});

// Listener for checking for certain actions
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === "ALLOW_URL") {
    allowedHosts.set(sender.tab.id, message.url);
    sendResponse({ ok: true });
  }

  if (message.type === "GET_TAB_STATE") {
    const memoryState = tabStates.get(message.tabId);

    if (memoryState) {
      sendResponse(memoryState);
      return true;
    }

    chrome.storage.session.get("tabState_" + message.tabId).then((data) => {
      sendResponse(
        data["tabState_" + message.tabId] || {
          phishing: false,
          signs: []
        }
      );
    });

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

// Removes tab state once the tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
  allowedHosts.delete(tabId);
  chrome.storage.session.remove("tabState_" + tabId);
});