const mainView = document.getElementById("mainView");
const whitelistView = document.getElementById("whitelistView");
const reportView = document.getElementById("reportView");

const openWhitelist = document.getElementById("openWhitelist");
const openReport = document.getElementById("openReport");

const backButton = document.getElementById("backButton");
const reportBackButton = document.getElementById("reportBackButton");

const addWhitelist = document.getElementById("addWhitelist");
const addBlacklist = document.getElementById("addBlacklist");

const whitelistInput = document.getElementById("whitelistInput");
const reportInput = document.getElementById("reportInput");

const whitelistBox = document.getElementById("whitelistBox");
const blacklistBox = document.getElementById("blacklistBox");

const themeToggle = document.getElementById("themeToggle");
const themeIcon = document.getElementById("themeIcon");

function applyTheme(isDarkMode) {
  if (isDarkMode) {
    document.body.classList.add("dark-mode");
    themeIcon.src = "/icons/moon_yellow.png";
    themeIcon.alt = "Light mode";
  } else {
    document.body.classList.remove("dark-mode");
    themeIcon.src = "/icons/moon.png";
    themeIcon.alt = "Dark mode";
  }
}

chrome.storage.local.get("darkMode").then((data) => {
  applyTheme(data.darkMode === true);
});

themeToggle.addEventListener("click", () => {
  const isDarkMode = !document.body.classList.contains("dark-mode");

  chrome.storage.local.set({ darkMode: isDarkMode }).then(() => {
    applyTheme(isDarkMode);
  });
});

function hideAllViews() {
  mainView.classList.add("hidden");
  whitelistView.classList.add("hidden");
  reportView.classList.add("hidden");
}

function showMainView() {
  hideAllViews();
  mainView.classList.remove("hidden");
}

function showWhitelistView() {
  hideAllViews();
  whitelistView.classList.remove("hidden");
  loadWhitelist();
}

function showReportView() {
  hideAllViews();
  reportView.classList.remove("hidden");
  loadBlacklist();

  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (
      tab?.url &&
      !tab.url.startsWith("chrome://") &&
      !tab.url.startsWith("chrome-extension://")
    ) {
      reportInput.value = tab.url;
    }
  });
}

function createListItem(site, removeType, reloadFunction) {
  const row = document.createElement("div");
  row.className = "whitelist-item";

  const siteText = document.createElement("span");
  siteText.textContent = site;

  const removeButton = document.createElement("button");
  removeButton.className = "remove-whitelist";
  removeButton.textContent = "-";

  removeButton.addEventListener("click", () => {
    chrome.runtime.sendMessage(
      {
        type: removeType,
        url: site
      },
      (response) => {
        if (response?.ok) {
          reloadFunction();
        }
      }
    );
  });

  row.appendChild(siteText);
  row.appendChild(removeButton);

  return row;
}

function loadWhitelist() {
  chrome.runtime.sendMessage({ type: "GET_WHITELIST" }, (response) => {
    whitelistBox.innerHTML = "";

    const whitelist = response?.whitelist || [];

    whitelist.forEach((site) => {
      whitelistBox.appendChild(
        createListItem(site, "REMOVE_FROM_WHITELIST", loadWhitelist)
      );
    });
  });
}

function loadBlacklist() {
  chrome.runtime.sendMessage({ type: "GET_BLACKLIST" }, (response) => {
    blacklistBox.innerHTML = "";

    const blacklist = response?.blacklist || [];

    blacklist.forEach((site) => {
      blacklistBox.appendChild(
        createListItem(site, "REMOVE_FROM_BLACKLIST", loadBlacklist)
      );
    });
  });
}

openWhitelist.addEventListener("click", showWhitelistView);
openReport.addEventListener("click", showReportView);

backButton.addEventListener("click", showMainView);
reportBackButton.addEventListener("click", showMainView);

addWhitelist.addEventListener("click", () => {
  const url = whitelistInput.value.trim();

  if (!url) return;

  chrome.runtime.sendMessage(
    {
      type: "ADD_TO_WHITELIST",
      url
    },
    (response) => {
      if (response?.ok) {
        whitelistInput.value = "";
        loadWhitelist();
      } else {
        alert(response?.error || "Could not whitelist URL");
      }
    }
  );
});

addBlacklist.addEventListener("click", () => {
  const url = reportInput.value.trim();

  if (!url) return;

  chrome.runtime.sendMessage(
    {
      type: "ADD_TO_BLACKLIST",
      url
    },
    (response) => {
      if (response?.ok) {
        reportInput.value = "";
        loadBlacklist();
      } else {
        alert(response?.error || "Could not blacklist URL");
      }
    }
  );
});

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