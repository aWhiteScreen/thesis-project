export const commonBrands = [
    "microsoft",
    "facebook",
    "netflix",
    "instagram",
    "roblox",
    "t-mobile",
    "paypal"
]

export async function brandAsSubdomain (url) {
    let subdomains = url.split(".");

    for (let i = 0; i < subdomains.length - 2; i++) {
        let subDomainParts = subdomains[i].split("-");
        for (const part of subDomainParts) {
            if (commonBrands.includes(part.toLowerCase())) {
                return true;
            }
        }
    }

    return false;

}