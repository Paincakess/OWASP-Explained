# **The OWASP Top 10 2021** Web App Security Risks

[A01:2021 - Broken Access Control](#**A01:2021 - Broken Access Control** )


## **A01:2021 - Broken Access Control** 

### **Description**
Access control refers to the enforcement of restrictions on authenticated users to perform actions outside of their level of permission. **Broken access control** occurs when such restrictions are not correctly enforced. This can lead to unauthorized access to sensitive information, as well as its modification or destruction.

### **Common Vulnerabilities of Access Controls are**:
- Tampering with parameters or modifying API requests to avoid access control checks.
- Providing **Insecure Direct Object References (IDOR)** which can be used view and modify information of other users.
- Escalating Privilege due to Bug or Design Flaw.
- Tampering with metadata, such as **JWT access control tokens, Cookies, Hidden Fields, and abusing JWT invalidation**
- Allowing API access from untrusted/unauthorized sources due to a **Cross-Origin Resource Sharing (CORS)** misconfiguration.
- Accessing API with no POST, PUT, and DELETE access controls in place.

### **Remediation**
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

### **Description**
Cryptographic failures refer to problems with cryptography or the absence of cryptography altogether which leads to **Sensitive Data Exposure**. This type of failure applies to the protection and secrecy of data in transit and at rest. Such data typically include authentication details, such as usernames and passwords, but also personally identifiable information (PII) such as personal and financial information, health records, business secrets, and more.

### **Vulnerabilities of Cryptographic Failures are**:
- Transmitting and Storing Sensitive data in clear texts.
- Use outdated or weak cryptographic algorithms and protocols or lack of encryption.
- Use of an insecure mode of operation.

### **Remediation**
- Classify data (processed, stored, or transmitted) that is transmitted by the application and identify which data is sensitive according to privacy laws, regulations, and Business needs.
- Implementing strong security controls and encryption depending on data classification.
- Use the Transport Layer Security (TLS) protocol with [forward secrecy](https://crashtest-security.com/enable-perfect-forward-secrecy/) to encrypt all data in transit.
- Using HTTP Strict Transport Security (HSTS) directive encryption or similar.
- Disabling caching for user responses that contain sensitive data.
- Using functions that always salts and hash passwords and have a work factor such as **brcrypt, scrypt, Argon2, PBKDF2** to store passwords.
- Using cryptographic random key generation and store the keys as byte arrays.

## **A03:2021 - Injection**
### **Description**
Injection Attacks refers to untrusted data by an application that forces it to execute commands. Such data or malicious code is inserted by an attacker and can compromise data or the whole application. When an injection attack is successful, the attacker can view, modify or even delete data and possibly gain control over the server. Most common injection attacks are **SQL Injection** and **Cross-site Scripting (XSS) attacks**, but other injection attacks can be **Code Injection, Command Injection, CSS Injection** and so on.

### **Vulnerabilities of Injection are**:
- Data supplied by users is not validated, filtered, or sanitized.
- The interpreter directly uses dynamic queries or non-parameterized calls without context-aware escaping.
- Hostile data is used directly, concatenated, or used within object-relational mapping (ORM) search parameters to extract additional, sensitive records.

### **Remediation**
- Most common solution is to use safe API that avoids the use of interpreter or uses parameterized queries and strongly sanitizing user inputs.
	- `parametrized stored procedures can still be vulnerable to an SQL injection if queries and data are concatenated`
- Using server-side input validation (Whitelisting), since many application requires the use of special characters.
- Use database controls within queries such as LIMIT to prevent mass exposure of data if an SQL injection is successful.

## **A04:2021 - Insecure Design** 

### **Description**
This category of vulnerabilities is focused on the risks associated with application's design flaws and architecture. It refers to the lack of security controls and business risk profiling in the development of software, and thereby the lack of proper determination of the degree of security design that is needed.

### **Remediation**
- Implement a secure development lifecycle with application security experts to assess the design security and privacy-related requirements
- Apply threat modeling methods to **critical authentication, access control, business logic, and key flows**
- Validate critical flows’ resistance to the threat model via unit and integration tests.

## **A05:2021 - Security Misconfiguration** 

### **Description**
Security misconfiguration refers to security controls that are not secured or not configured properly. Basically, Misconfiguration vulnerabilities are configuration weaknesses that may exist in software components and subsystems or in user administration.

### **Vulnerabilities of Security Misconfiguration are**:
- Wrongly configured permissions and lack of security Hardening
- Unnecessary features, such as ports, services, pages, accounts, or privileges are allowed or installed.
- Default accounts/passwords are enabled or unchanged.
- Error messages displayed containing stack traces or other sensitive information.
- The latest security features are not enabled or implemented correctly.
- Security headers or directives are not sent by the server or are not set to secure values.
- Outdates software and services being used.

### **Remediation**
- Review and update of the configurations of all security notes, updates, and patches as part of the patch management process.
- Implementing segmented application architecture via segmentation, containerization, or cloud security groups to separate tenants and components.
- Do not install or remove unnecessary features and frameworks.
- Implementation of Security Directives and Security Headers.

## **A06:2021 - Vulnerable and Outdated Components**

### **Description**
Component-based vulnerabilities occur when a software component is unsupported, out of date, or vulnerable to a known exploit. Organizations may inadvertently use vulnerable software components in production environments, posing a threat to the web application. Since many software components run with the same privileges as the application itself, any vulnerabilities or flaws in the component can result in a threat to the web application.

### **Vulnerabilities of  Vulnerable and Outdated Components are**:

- Not being aware of the versions of client-side and server-side components that you use.
- If the software is vulnerable, unsupported, or out of date, which includes the operating systems, web/application server, database management system (DBMS), applications, APIs and any components, runtime environments, and libraries.
- Not fixing or upgrading the platform, framework, and dependencies when patches come out.
- Not performing tests on the compatibility of updated, upgraded, or patched libraries.
- components’ configurations used by the application are not secured.

### **Remediation**
- Remove any unused dependencies, unnecessary features, components, files, and documentation.
- Use only official sources and secure links to obtain components.
- Look out for libraries and components that are not being maintained and do not have security patches for old versions.

## **A07:2021 - Identification and Authentication Failure**

### **Description**
Identification and authentication failures previously known as **Broken Authentication** can occur when functions related to a user's identity, authentication, or session management are not implemented correctly or not adequately protected by an application. Attackers may be able to exploit identification and authentication failures by **compromising passwords, keys, session tokens, or exploit other implementation flaws** to assume other users' identities, either temporarily or permanently.

### **Vulnerabilities of  Identification and Authentication failure are**:
- When application is not protected against automated attacks such as credential stuffing.
- Accepts the use of **default, weak, or well-known passwords**.
- Have weak or ineffective credential recovery and forgotten password procedures.
- Employs plain text, encrypted, or weakly hashed password data stores.
- Exposes the session identified in the URL and Reuses the session identified after login.
- Does not properly **invalidate user sessions and authentication tokens during logout or when inactive**.

### **Remediation**
- Implementing multi-factor authentication, whenever possible, to hinder credential stuffing, brute force, and stolen credential reuse attacks.
- Use of complex and strong password policies and determine password length, complexity, and rotation policies.
- Harden registration, credential recovery, and API pathways against account enumeration attacks through the use of identical messages for all outcomes.
- Limit or progressively delay repeated login attempts after failure by monitoring failed attempts.
- Utilize a server-side, secure, and built-in session manager that generates new random session IDs with high entropy after login.

## **A08:2021 - Software and Data Integrity Failures**

### **Description**
Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This can occur when you use software from untrusted sources and repositories or even software that has been tampered with at the source, in transit, or even the endpoint cache.
Attackers can exploit this to potentially introduce unauthorized access, malicious code, or system compromise as part of the following attacks, **Cache Poisoning, Code injection, Command execution, Denial of Service(DOS)**.

### **Remediation**
- Use mechanisms such as digital signatures to verify that software or data from a source has not been tampered or modified.
- Use a software supply chain security tool to make sure that components do not have any known vulnerabilities.
- Implement thorough segregation, configuration, and access control to your CI/CD pipeline to guarantee the integrity of the code that flows through the build and deploy processes
- Make sure no unsigned or unencrypted serialized data is sent to untrusted clients without a prior integrity check or digital signature to detect tampering or replay of the data.

## **A09:2021 - Security Logging and Monitoring Failures**

### **Description**
Security logging and monitoring failures are frequently a factor in major security incidents. Failure to sufficiently log, monitor, or report security events, such as login attempts, makes suspicious behavior difficult to detect and significantly raises the likelihood that an attacker can successfully exploit the application.

### **Vulnerabilities of  Security Logging and Monitoring failure are**:
- Logins, failed logins, high-value transactions, and other types of auditable events are not logged.
- Inadequate, unclear, or no messages are generated by warnings and errors.
- API and application logs are not examined for suspicious activity.
- Alerts are not triggered by penetration testing or scans by dynamic application security testing tools.
- The application cannot detect, escalate, or alert for active attacks in real-time or near real-time.

### **Remediation**
- Log all login, access control, and server-side input validation failures with sufficient user context to spot suspicious or malicious accounts. Store them long enough to perform delayed forensic analysis.
- Making sure logs are in a format that can be easily consumed by log management solutions.
- Implement an audit trail with integrity controls for high-value transactions such as append-only database tables to prevent tampering or deletion.
- Establishing effective monitoring and alerting to detect suspicious activities.

## **A10:2021 - Server Side Request Forgery (SSRF)**

### **Description**
Server-side request forgery (SSRF) flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. The vulnerable web application will often have privileges to read, write, or import data using a URL. The attacker abuses the functionality on the server to read or update internal resources. The attacker can then force the application to send requests to access unintended resources, often bypassing security controls.

Fetching a URL is a common feature among modern web applications, which results in increases in instances of SSRF. Moreover, these are also becoming more severe due to the increasing complexity of architectures and cloud services.

### **Remediation**
- Reduce the impact of SSRF by segmenting the remote resource access functionality in separate networks.
- Block all but essential traffic by instituting “deny by default” network policies or network access control rules.
- All client-supplied input data must be sanitized and validated.
- Use a positive allow list to enforce the URL schema, port, and destination and Disabling HTTP redirections.
- Do not send raw responses to clients.