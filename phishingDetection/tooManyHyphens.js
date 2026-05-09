export function tooManyHyphens(url) {

    let hyphenCount = 0; 

    for(let i = 0; i < url.length; i++) {
      if (url[i] == "-") {
        hyphenCount++;
      }
    }

    if (hyphenCount >= 2) {
      return true;
    } else return false;
}