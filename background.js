function isNotHTTPS(url) {
  return url.startsWith("http://");
}

const warningPage = chrome.runtime.getURL("warning.html");

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {

  // Will change to true if any phishing is detected 
  let phishing = false;

  // Only check when loading a new URL
  if (!changeInfo.url) return;

  // Checks if the URL is the extension itself or a new page, which should be ignored
  if (changeInfo.url.startsWith("chrome-extension://") || changeInfo.url.startsWith("about:blank") || changeInfo.url.startsWith("chrome://newtab/")) return;
  
  if (isNotHTTPS(changeInfo.url)) {
    console.log("Suspicious URL detected:");
    phishing = true;
  }

  console.log("Checking changeinfo URL:", changeInfo.url);

  // If phishing is detected, redirect to the warning page
  if (phishing) {
    chrome.tabs.update(tabId, { url: warningPage });
}

}); 