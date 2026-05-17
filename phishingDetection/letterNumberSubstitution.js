export function letterNumberSubstitution(url) {

    // Remove dots (so subdomains don't interfere)
  const compactURL = url.toLowerCase().split(/[.-]/);

  for (let i = 0; i < compactURL.length; i++) {
    const part = compactURL[i];

    if (/[a-z]/.test(part) && /\d/.test(part)) {
      return true;
    }
  }

  return false;

}
