const params = new URLSearchParams(window.location.search);

const originalUrl = params.get("url");
const phishingSigns = JSON.parse(params.get("signs") || "[]");

const urlElement = document.getElementById("url");


// Highlight HTTP in the URL
if (originalUrl.startsWith("http://")) {
  urlElement.innerHTML =
    `<span class="tooltip-highlight">
      http
      <span class="tooltip-text">
        HTTP being used instead of HTTPS is a common sign of phishing.
      </span>
    </span>` +
    originalUrl.slice(4);
} else {
  urlElement.textContent = originalUrl;
}

const signsList = document.getElementById("signs");

// Display the list of phishing signs for now as text
phishingSigns.forEach(sign => {
  const li = document.createElement("li");
  li.textContent = sign;
  signsList.appendChild(li);
});

document.getElementById("backButton").addEventListener("click", () => {
  window.location.href = "about:blank";
});