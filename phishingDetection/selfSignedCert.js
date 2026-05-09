export function selfSignedCert(subject, issuer) {
  if (JSON.stringify(subject) === JSON.stringify(issuer)) {
    return true;
  } else return false;
}