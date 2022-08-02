# **The OWASP Top 10 2021** Web App Security Risks

## **A01:2021 - Broken Access Control** 
**Description**
Access control refers to the enforcement of restrictions on authenticated users to perform actions outside of their level of permission. **Broken access control** occurs when such restrictions are not correctly enforced. This can lead to unauthorized access to sensitive information, as well as its modification or destruction.

**Common Vulnerabilities of Access Controls are**:
- Tampering with parameters or modifying API requests to avoid access control checks.
- Providing **Insecure Direct Object References (IDOR)** which can be used view and modify information of other users.
- Escalating Privilege due to Bug or Design Flaw.
- Tampering with metadata, such as **JWT access control tokens, Cookies, Hidden Fields, and abusing JWT invalidation**
- Allowing API access from untrusted/unauthorized sources due to a **Cross-Origin Resource Sharing (CORS)** misconfiguration.
- Accessing API with no POST, PUT, and DELETE access controls in place.

**Remediation**
- Introducing access control mechanisms and re-using them repeatedly in the application.
- Monitoring and recording failed access control attempts and alerting the administrators when necessary.
- Invalidating stateful session identifiers on the server after logout.
- Make stateless JSON web tokens (JWT) short-lived.
- Ensuring that no metadata (git) nor backup files are present in web roots.
- Disabling webserver directory listing.
- Reducing the effect of automated attack tools by rate-limiting API and controller access.
- Deleting any inactive or unnecessary accounts.
- Using multi-factor authentication at all access points and Deleting unnecessary access points.
- Eliminating services that are not needed on your server.

## **A02:2021 - Cryptographic Failures** 
**Description**
Cryptographic failures refer to problems with cryptography or the absence of cryptography altogether which leads to **Sensitive Data Exposure**. This type of failure applies to the protection and secrecy of data in transit and at rest. Such data typically include authentication details, such as usernames and passwords, but also personally identifiable information (PII) such as personal and financial information, health records, business secrets, and more.

**Common Vulnerabilities of Access Controls are**:
- Transmitting and Storing Sensitive data in clear texts.
- Use outdated or weak cryptographic algorithms and protocols or lack of encryption.
- Use of an insecure mode of operation.

**Remediation**
- Classify data (processed, stored, or transmitted) that is transmitted by the application and identify which data is sensitive according to privacy laws, regulations, and Business needs.
- Implementing strong security controls and encryption depending on data classification.
- Use the Transport Layer Security (TLS) protocol with [forward secrecy](https://crashtest-security.com/enable-perfect-forward-secrecy/) to encrypt all data in transit.
- Using HTTP Strict Transport Security (HSTS) directive encryption or similar.
- Disabling caching for user responses that contain sensitive data.
- Using functions that always salts and hash passwords and have a work factor such as **brcrypt, scrypt, Argon2, PBKDF2** to store passwords.
- Using cryptographic random key generation and store the keys as byte arrays.

## **A03:2021 - Injection**
**Description**
An Injection Attack refers to untrusted data by an application that forces it to execute commands. Such data or malicious code is inserted by an attacker and can compromise data or the whole application.