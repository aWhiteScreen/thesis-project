export function normalizeHostname(input) {
  try {
    if (!input.startsWith("http://") && !input.startsWith("https://")) {
      input = "https://" + input;
    }

    return new URL(input).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return null;
  }
}