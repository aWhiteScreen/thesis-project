export const commonBrands = [
    "microsoft",
    "facebook",
    "netflix",
    "instagram",
    "roblox"
]

export function brandAsSubdomain (url) {
    let subdomains = url.split(".");

    for (let i = 0; i < subdomains.length - 2; i++) {
        if (commonBrands.includes(subdomains[i].toLowerCase())) {
            return true;
        }
    }

    let mainDomainParts = url.split("-");
    for (let i = 0; i < mainDomainParts.length - 1; i++) {
        if (commonBrands.includes(mainDomainParts[i].toLowerCase())) {
            return true;
        }
    }

    return false;

}