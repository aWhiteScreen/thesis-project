export const shorteners = [
    "bit.ly",
    "tinyurl.com",
    "ow.ly"
]

export function shortenedURL(url) {

    if (shorteners.includes(url)) {
        return true;
    } else {
        return false;
    }

}