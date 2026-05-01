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

phishingSigns.forEach(sign => {
  const li = document.createElement("li");
  li.textContent = sign;
  signsList.appendChild(li);
});

document.getElementById("backButton").addEventListener("click", () => {
  window.location.href = "about:blank";
});


 
document.getElementById("continueButton").addEventListener("click", () => {
  // Send message to background.js so phishing doesn't trigger again immediately
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