# PigeonGuard

## Description:

PigeonGuard is an extension for Google Chrome that can detect signs of phishing in the URL of a website. It was made as a project for a bachelor's final thesis on "Users' protection from phishing attacks.".

### How to use:

1) Download the add-on from here.
2) Extract the add-on at a convenient place.
3) On Chrome, enter chrome://extensions/ or click on the add-on icon and click "Manage extensions".
4) In the upper-right corner make sure developer mode is turned on.
5) Click on "Load unpacked" and select the folder with the extracted add-on.

### Example websites:

1) https://examp1eb4nk.com/ - Letters are substituted with numbers.
2) https://self-signed.badssl.com - Self-signed SSL certificate.
3) http://httpforever.com/ - Uses HTTP instead of HTTPS.
4) https://bit.ly/1sNZMwL - Uses a URL shortener.
5) https://paypal.verify-login.example.com/ - Multiple subdomains and common brand used as subdomain.
6) http://192.168.1.1/ - IP used instead of a regular domain.
7) https://too-many-hyphens.cfd/and/too/many/slashes - Top level domain that is associated with phishing and a high amount of special characters such as "-" and "/".
8) https://krepsinis.net@facebook.com/ - Redirection to another URL using the @ sign.