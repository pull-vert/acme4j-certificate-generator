# ACME4J Certificate Generator

**acme4j-certificate-generator** is a tool with is a single main class written in Kotlin, that helps connecting to an ACME server, and performing all necessary steps to manage free certificates from Let's Encrypt :
* Create a private key for your Let's Encrypt account
* Create a Let's Encrypt account using the private key generated in the previous phase
* Create a certificate order and send it to Acme4J, to obtain a certificate

It is based on the [ACME 4J](https://github.com/shred/acme4j) librairy.

Acme4j is a Java toolkit that enables you to automate the creation of free TLS / SSL certificates.
Acme4J is obtaining the TLS / SSL certificates by communicating with the Let's Encrypt certificate authority (CA).
Automating certificate generation is a big advantage over updating certificates manually.
When automated you save time, and you can changes certificates more often, reducing the risk of your certificate getting compromised.

**acme4j-certificate-generator** Requires JRE 8 (update 101) or higher

## Usage

## Note from author
I followed [Jenkov Acme4J Tutorial](http://tutorials.jenkov.com/acme4j/index.html) to code this tool.