import { commonBrands } from "./phishingDetection/brandAsSubdomain.js";

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
  return /[a-z]/i.test(part) && /\d/.test(part);
}

function appendHighlightedSlashPart(text) {
  for (const char of text) {
    if (char === "/") {
      urlElement.appendChild(
        createHighlight(
          char,
          "An excessive number of slashes (5 or more) suggests an increased chance of phishing since they can be used to obfuscate suspicious parts of a URL."
        )
      );
    } else {
      urlElement.append(char);
    }
  }
}

function appendHighlightedHostnamePart(part, isLastPart, phishingSigns) {
  const lowerPart = part.toLowerCase();

  const brand = commonBrands.find((brand) =>
    lowerPart.includes(brand.toLowerCase())
  );

  if (phishingSigns.includes("SUSPICIOUS_TLD") && isLastPart) {
    urlElement.appendChild(
      createHighlight(
        part,
        "Atypical top level domains are often used in phishing websites as they are free and easy to acquire."
      )
    );
    return;
  }

  let i = 0;

  while (i < part.length) {
    if (phishingSigns.includes("PLAGIARIZED_BRAND") && brand) {
      const brandIndex = lowerPart.indexOf(brand.toLowerCase());

      if (i === brandIndex) {
        urlElement.appendChild(
          createHighlight(
            part.slice(i, i + brand.length),
            "A common brand being used as anything other than as the main domain part is a common phishing tactic to create a URL that looks similar to its legitimate counterpart."
          )
        );

        i += brand.length;
        continue;
      }
    }

    if (phishingSigns.includes("AT_SIGN") && part[i] === "@") {
      urlElement.appendChild(
        createHighlight(
          part[i],
          "@ is typically not used in legitimate website URLs but is a common symbol used by phishers since it can imitate 'a' or redirect to another website."
        )
      );

      i++;
      continue;
    }

    if (phishingSigns.includes("TOO_MANY_HYPHENS") && part[i] === "-") {
      urlElement.appendChild(
        createHighlight(
          part[i],
          "Legitimate websites typically do not use more than 1 hyphen. 2 or more hyphens suggest an increased chance of phishing."
        )
      );

      i++;
      continue;
    }

    if (
      phishingSigns.includes("LETTER_SUBSTITUTION_WITH_NUMBERS") &&
      isLetterNumberSubstitution(part) &&
      /\d/.test(part[i])
    ) {
      urlElement.appendChild(
        createHighlight(
          part[i],
          "Numbers can be used in phishing URLs to substitute letters with familiar looking numbers to try and trick the user into believing it is a legitimate URL."
        )
      );

      i++;
      continue;
    }

    urlElement.append(part[i]);
    i++;
  }
}

function displayHighlightedUrl(originalUrl, phishingSigns) {
  urlElement.textContent = "";

  const parsedUrl = new URL(originalUrl);

  const protocol = parsedUrl.protocol;
  const authority =
    (parsedUrl.username || parsedUrl.password
      ? parsedUrl.username +
        (parsedUrl.password ? ":" + parsedUrl.password : "") +
        "@"
      : "") + parsedUrl.hostname;

  const hostname = authority;

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

  if (phishingSigns.includes("SHORTENED_URL")) {
    urlElement.appendChild(
      createHighlight(
        parsedUrl.hostname,
        "URL shorteners such as TinyURL and Bitly can be used by phishers to redirect you to an unknown phishing link that is unseen to you."
      )
    );
  } else {
    const hostnameParts = hostname.split(".");

    hostnameParts.forEach((part, index) => {
      const isLastPart = index === hostnameParts.length - 1;

      appendHighlightedHostnamePart(part, isLastPart, phishingSigns);

      if (!isLastPart) {
        urlElement.append(".");
      }
    });
  }

  if (restOfUrl) {
    if (phishingSigns.includes("TOO_MANY_SLASHES")) {
      appendHighlightedSlashPart(restOfUrl);
    } else {
      urlElement.append(restOfUrl);
    }
  }
}

displayHighlightedUrl(originalUrl, phishingSigns);

const otherPhishingSigns = document.getElementById("otherPhishingSigns");
const signsList = document.getElementById("signs");

let otherPhishingSignsPresent = false;

const phishingSignMessages = {
  SELF_SIGNED_SSL:
    "The SSL/TLS certificate is self-signed rather than signed by a recognized Certificate Authority which indicates an increased chance of phishing.",
  LONG_URL:
    "The URL matches or exceeds the length of a typical phishing URL. Long URLs may used to obfuscate suspicious elements from the user.",
  NO_RECORD:
    "This URL has no WHOIS record associated with it which indicates an increased chance of phishing since phishing websites have short lifespans and do not always get logged.",
  BLACKLISTED_BY_USER:
    "This URL was blacklisted by the user for, potentially, being a phishing URL.",
  BLACKLISTED_BY_GOOGLE:
    "The URL has been blacklisted by Google as a harmful website that may include phishing.",
  YOUNG_DOMAIN:
    "This domain is younger than 6 months which indicates an increased chance of phishing. Legitimate domains tend to be older.",
  DOMAIN_MISMATCH:
    "The registered domain and the domain provided in the URL do not match. This indicates an increased chance of phishing since the URL may be attempting to imitate another brand.",
  MULTIPLE_SUBDOMAINS:
    "This URL contains 2 or more subdomains which is a tactic often used by phishers to create more legitimate looking URLs by adding keywords such as 'support', 'account' next to a legitimate sounding name."
};

phishingSigns.forEach((sign) => {
  const message = phishingSignMessages[sign];

  if (!message) {
    return;
  }

  otherPhishingSignsPresent = true;

  const box = document.createElement("div");
  box.className = "phishing-sign-box";
  box.textContent = message;

  signsList.appendChild(box);
});

otherPhishingSigns.style.display = otherPhishingSignsPresent ? "block" : "none";

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

continueLink.addEventListener("click", (event) => {
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