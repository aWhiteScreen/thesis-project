export async function isNotHTTPS(protocol) {

  if(protocol !== "https:") {
    return true;
  } else return false;
}