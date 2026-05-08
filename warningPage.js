const params = new URLSearchParams(window.location.search);

const originalUrl = params.get("url");
const phishingSigns = JSON.parse(params.get("signs") || "[]");

const urlElement = document.getElementById("url");

function createHighlight(text, tooltip) {
  const span = document.createElement("span");
  span.className = "tooltip-highlight";
  span.textContent = text;

  const tooltipSpan = document.createElement("span");
  tooltipSpan.className = "tooltip-text";
  tooltipSpan.textContent = tooltip;

  span.appendChild(tooltipSpan);

  return span;
}

function isLetterNumberSubstitution(part) {
  if (!/[a-z]/i.test(part) || !/\d/.test(part)) {
    return false;
  }

  return /[a-z]+\d+[a-z]+/i.test(part);
}

function appendHighlightedSubstitutionPart(part) {
  for (const char of part) {
    if (/\d/.test(char)) {
      urlElement.appendChild(
        createHighlight(
          char,
          "Numbers are typically not used in legitimate URLs but they are often used by phishers to mimic URL symbols or to lengthen the URL. "
        )
      );
    } else {
      urlElement.append(char);
    }
  }
}

function appendHighlightedHyphenPart(part) {
  for (const char of part) {
    if (char == '-') {
      urlElement.appendChild(
        createHighlight(
          char,
          "2 or more hyphens are often used in phishing attacks to construct more trustworthy looking domains."
        )
      )
    } else urlElement.append(char);
  }
}

function appendHighlightedSlashPart(text) {
  for (const char of text) {
    if (char === "/") {
      urlElement.appendChild(
        createHighlight(
          char,
          "Excessive slashes in a URL can indicate obfuscation, which is common in phishing attempts."
        )
      );
    } else {
      urlElement.append(char);
    }
  }
}

function displayHighlightedUrl(originalUrl, phishingSigns) {
  urlElement.textContent = "";

  const parsedUrl = new URL(originalUrl);

  const protocol = parsedUrl.protocol;
  const hostname = parsedUrl.hostname;

  const restOfUrl =
    (parsedUrl.port ? ":" + parsedUrl.port : "") +
    parsedUrl.pathname +
    parsedUrl.search +
    parsedUrl.hash;

  if (phishingSigns.includes("NOT_HTTPS") && protocol === "http:") {
    urlElement.appendChild(
      createHighlight(
        "http",
        "HTTP being used instead of HTTPS is a common sign of phishing."
      )
    );
    urlElement.append(":");
  } else {
    urlElement.append(protocol);
  }

  if (phishingSigns.includes("TOO_MANY_SLASHES")) {
    appendHighlightedSlashPart("//");
  } else {
    urlElement.append("//");
  }

  const hostnameParts = hostname.split(".");

  hostnameParts.forEach((part, index) => {
    const isLastPart = index === hostnameParts.length - 1;

    if (
      phishingSigns.includes("LETTER_SUBSTITUTION_WITH_NUMBERS") &&
      isLetterNumberSubstitution(part)
    ) {
      appendHighlightedSubstitutionPart(part);
    } else if (
      phishingSigns.includes("SUSPICIOUS_TLD") &&
      isLastPart
    ) {
      urlElement.appendChild(
        createHighlight(
          part,
          "Atypical top level domains are often used in phishing websites as they are free and easy to acquire."
        )
      );
    } else if (phishingSigns.includes("TOO_MANY_HYPHENS") && part.includes("-")) {
      appendHighlightedHyphenPart(part);
    } else {
      urlElement.append(part);
    }

    if (!isLastPart) {
      urlElement.append(".");
    }
  });

  if (restOfUrl) {
    if (phishingSigns.includes("TOO_MANY_SLASHES")) {
      appendHighlightedSlashPart(restOfUrl);
    } else {
      urlElement.append(restOfUrl);
    }
  }
}

displayHighlightedUrl(originalUrl, phishingSigns);

const signsList = document.getElementById("signs");

const phishingSignMessages = {
  SELF_SIGNED_SSL:
    "The SSL/TLS certificate is self-signed rather than signed by a recognized Certificate Authority which indicates an increased chance of phishing.",
  LONG_URL:
    "The URL matches or exceeds the length of a typical phishing URL. Long URLs may used to obfuscate suspicious elements from the user.",
  TOO_MANY_HYPHENS:
    "Legitimate websites typically do not use more than 1 hyphen. 2 or more hyphens suggest an increased chance of phishing.",
  TOO_MANY_SLASHES:
    "An excessive number of slashes (5 or more) suggests in increased chance of phishing.",
  NO_RECORD:
    "This URL has no WHOIS record associated with it which indicates an increased chance of phishing since phishing websites have short lifespans and do not always get logged.",
  BLACKLISTED_BY_USER:
    "This URL was blacklisted by the user for, potentially, being a phishing URL.",
  BLACKLISTED_BY_GOOGLE:
    "The URL has been blacklisted by Google as a harmful website that may include phishing.",
  YOUNG_DOMAIN:
    "This domain is younger than 6 months which indicates an increased chance of phishing. Legitimate domains tend to be older.",
  DOMAIN_MISMATCH:
    "The registered domain and the domain provided in the URL do not match. This indicates an increased chance of phishing since the URL may be attempting to imitate another brand."
};

phishingSigns.forEach(sign => {
  const message = phishingSignMessages[sign];

  if (!message) {
    return;
  }

  const box = document.createElement("div");
  box.className = "phishing-sign-box";
  box.textContent = message;

  signsList.appendChild(box);
});


document.getElementById("backButton").addEventListener("click", () => {
  window.location.href = "about:blank";
});


const detailsToggle = document.getElementById("detailsToggle");
const detailsSection = document.getElementById("detailsSection");
const continueLink = document.getElementById("continueLink");

detailsSection.style.display = "none";
detailsToggle.textContent = "Show details";

detailsToggle.addEventListener("click", () => {
  const isHidden = detailsSection.style.display === "none";

  detailsSection.style.display = isHidden ? "block" : "none";
  detailsToggle.textContent = isHidden ? "Hide details" : "Show details";
});

continueLink.addEventListener("click", event => {
  event.preventDefault();

  chrome.runtime.sendMessage(
    {
      type: "ALLOW_URL",
      url: new URL(originalUrl).hostname
    },
    () => {
      window.location.href = originalUrl;
    }
  );
});