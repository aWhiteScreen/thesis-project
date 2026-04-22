chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    console.log("Checking URL:", tab.url);

    // Placeholder for phishing detection logic
    if (tab.url.includes("@")) {
      console.log("Suspicious URL detected!");
    }
  }
});