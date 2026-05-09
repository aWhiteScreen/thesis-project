export function letterNumberSubstitution(url) {

    // Remove dots (so subdomains don't interfere)
    const compactURL = url.split(".");

    for (let i = 0; i < compactURL.length; i++) {
      if (!/[a-z]/.test(compactURL[i]) || !/\d/.test(compactURL[i])) {
        continue;
      }
      else if (/[a-z]+\d+[a-z]+/.test(compactURL[i])) {
        return true;
      }
    }

    return false;

}