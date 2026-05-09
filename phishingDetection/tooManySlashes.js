export function tooManySlashes(url) {

    let slashCount = 0; 

    for(let i = 0; i < url.length; i++) {
      if (url[i] == "/") {
        slashCount++;
      }
    }

    if (slashCount >= 5) {
      return true;
    } else return false;
}