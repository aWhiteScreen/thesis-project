chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  chrome.runtime.sendMessage(
    {
      type: "GET_TAB_STATE",
      tabId: tab.id
    },
    (state) => {
      const icon = document.getElementById("statusIcon");
      const text = document.getElementById("statusText");
      const img = document.getElementById("statusImg");

      if (state?.phishing) {
        icon.className = "status-icon danger";
        img.src = "/icons/warning128x128.png";
        text.textContent = "Current page may be unsafe";
      } else {
        icon.className = "status-icon safe";
        img.src = "/icons/safety128x128.png";
        text.textContent = "Current page is secure";
      }
    }
  );
});