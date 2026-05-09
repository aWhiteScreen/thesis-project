export function suspiciousTLD(url) {
    const tlds = [
      "win",
      "help",
      "bond",
      "cfd",
      "finance",
      "world",
      "top",
      "icu",
      "support",
      "vip",
      "cyou",
      "pro",
      "sbs",
      "monster",
      "mom",
      "click",
      "quest",
      "buzz",
      "ink",
      "fyi"
    ];

    const urlTLD = url.split(".").pop();

    if (tlds.includes(urlTLD)) {
      return true;
    } else {
      return false;
    }

}