/*
 * Copyright 2018 ACME4J Certificate Generator's author : Frédéric Montariol. Use of this source code is governed by the Apache 2.0 license.
 */

package org.pullvert.certificate

import org.shredzone.acme4j.*
import org.shredzone.acme4j.challenge.Http01Challenge
import org.shredzone.acme4j.util.CSRBuilder
import org.shredzone.acme4j.util.KeyPairUtils
import java.io.FileReader
import java.io.FileWriter
import java.security.KeyPair
import java.time.Instant


private val letsEncryptDefaultStagingUrl = "acme://letsencrypt.org/staging"

fun main() {
    // get properties
   when(System.getProperty("operation")) {
       "" -> { val t = true }
       else -> false
   }
}

/**
 * Create and then save on filesystem a RSA private / public key pair
 *
 * @param keyPairFile The path to the pem file that will store key pair
 * @param keySize The key Size (with 2048 default value)cvb
 */
private fun createAndSaveKeyPair(keyPairFile: String, keySize: Int = 2048): KeyPair {
    assert(keyPairFile.endsWith(".pem")) { "private / public key pair File must end with .pem"}
    // Create a new RSA private / public key pair
    val accountKeyPair = KeyPairUtils.createKeyPair(keySize)

    // Write key to disk, so it can be reused another time
    FileWriter(keyPairFile).use { fileWriter -> KeyPairUtils.writeKeyPair(accountKeyPair, fileWriter) }
    return accountKeyPair
}

/**
 * Create and then save on filesystem a Let's Encrypt account
 *
 * @param keyPairFile The path to the pem file containing your private key
 * @param accountUrlFile The path to the txt file that will store the returned account URL in
 * @param letsEncryptUrl The URL to the Let's Encrypt API endpoint (with default value)
 */
private fun createAndSaveLetsEncryptAccount(keyPairFile: String, accountUrlFile: String, letsEncryptUrl: String = letsEncryptDefaultStagingUrl): Account {
    assert(keyPairFile.endsWith(".pem")) { "private / public key pair File must end with .pem"}
    assert(accountUrlFile.endsWith(".txt")) { "account location File must end with .txt to store your account URL"}

    val keyPair = KeyPairUtils.readKeyPair(FileReader(keyPairFile))

    val session = Session(letsEncryptUrl)
    // Create a new Let's Encrypt account
    val account = AccountBuilder()
        //.onlyExisting()
        .useKeyPair(keyPair)
        .agreeToTermsOfService()
        .create(session)

    // Write account URL to disk, so it can be reused another time
    FileWriter(accountUrlFile).use({ fileWriter -> fileWriter.write(account.location.toString()) })
    return account
}

private fun createAndSaveLetsEncryptCertificate(
    account: Account,
    validUntil: Instant,
    vararg domains: String
) {
    // create an Order object representing a certificate order
    val order = account.newOrder()
        .domains(*domains)
        .notAfter(validUntil)
        .create()

    // The response is a set of authorizations which you have to process in order to get the requested certificate
    // There will be one authorization per domain in your certificate order.
    // The authorization verifies to Let's Encrypt that you actually own the domain you are requesting a certificate for
    for (auth in order.authorizations) {
        if (auth.status != Status.VALID) {
            processAuth(auth)
        }
    }

    createCertificateSigningRequest(order, *domains)

    downloadCertificate(order)
}

private fun processAuth(auth: Authorization) {
    // The HTTP challenge consists of Let's Encrypt giving you some data that you need to upload to your web server hosting the given domain.
    // Let's Encrypt will then download that data - and if successful - will consider that as a confirmation that you own (or at least administer)
    // the given domain
    // Within the Authorization object (the auth parameter) there are one or more challenges, of which one must be met.
    // Here we specifically look for an HTTP authorization object
    val challenge = auth.findChallenge<Http01Challenge>(Http01Challenge.TYPE)!!

    val fileName = challenge.token
    val fileContent = challenge.authorization
//    val domain = challenge.domain

    // todo : upload fileContent
    // Before the challenge is triggered, you must read the value from challenge.getAuthorization() and upload it in a file to your web server. The URL the value must be available at, is:
    // http://${domain}/.well-known/acme-challenge/${token}
    // where ${domain} is the domain for which you are requesting the domain for (returned by challenge.getDomain() ), and ${token} is the value returned by challenge.getToken().

    // example : https://github.com/shred/acme4j/blob/master/acme4j-example/src/main/java/org/shredzone/acme4j/ClientTest.java

    challenge.trigger()

    while (auth.status != Status.VALID) {
        Thread.sleep(3000L)
        auth.update()
    }
}

private fun createCertificateSigningRequest(order: Order, vararg domains: String) {
    val domainKeyPair = KeyPairUtils.createKeyPair(2048) // todo parameter

    val csrb = CSRBuilder()
    for (domain in domains) {
        csrb.addDomain(domain)
    }
    csrb.setOrganization("Jenkov Aps") // todo parameter
    csrb.sign(domainKeyPair)
    val csr = csrb.encoded

    csrb.write(FileWriter("example.csr")) // todo parameter

    order.execute(csr)
}

private fun downloadCertificate(order: Order) {
    while (order.status != Status.VALID) {
        Thread.sleep(3000L)
        order.update()
    }

    val cert = order.certificate

    FileWriter("jenkov-com-cert-chain.crt").use { fw -> cert!!.writeCertificate(fw) } // todo parameter
}
