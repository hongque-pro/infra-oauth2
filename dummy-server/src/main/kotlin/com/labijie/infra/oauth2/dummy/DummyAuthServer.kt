package com.labijie.infra.oauth2.dummy

import com.labijie.infra.oauth2.OAuth2Utils
import com.labijie.infra.oauth2.TwoFactorPrincipal
import com.labijie.infra.oauth2.TwoFactorSignInHelper
import com.labijie.infra.oauth2.annotation.EnableOAuth2Server
import com.labijie.infra.oauth2.annotation.OAuth2ServerType
import com.labijie.infra.oauth2.annotation.TokenStoreType
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.jwt.crypto.sign.RsaVerifier
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.util.Base64Utils
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-21
 */
@EnableOAuth2Server(OAuth2ServerType.Authorization, OAuth2ServerType.Resource, tokeStore = TokenStoreType.InMemory)
@SpringBootApplication
@RestController
class DummyAuthServer {

    @Autowired
    private lateinit var twoFactorSignInHelper: TwoFactorSignInHelper

    @RequestMapping("/2f")
    fun test2FRequired(): String {
        return "I am 2f test"
    }

    @RequestMapping("/attached")
    fun testAttached(): TwoFactorPrincipal {
        val current =  OAuth2Utils.currentTwoFactorPrincipal()
        return current
    }

    @RequestMapping("/self")
    fun self(): TwoFactorPrincipal {
        val current =  OAuth2Utils.currentTwoFactorPrincipal()
        return current
    }

    @RequestMapping("/login")
    fun login(): ResponseEntity<OAuth2AccessToken> {
        val token = twoFactorSignInHelper.signInTwoFactor()
        return ResponseEntity(token, HttpStatus.OK)
    }
}


fun main(args: Array<String>) {
    val v = RsaVerifier("-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyK2x/ADszOVEkYhVAjaH\n" +
            "ObFms8qj5dSnpLVeCcLIzUwQEs6GdveMut8cSX7XEKtgXss1B4gNJMzJmI1b4JYx\n" +
            "3uYxSTAijthEmTNuhcMcqribx10hTVgHNt92F822MTvBDxAmIUWNt2LCV8bKCHXg\n" +
            "xe/DMGNrWnqP/1+7qcxcydeyrzKSMOiJNs6lDuRSVYm+XgGA3PzAl/78Qh63buCg\n" +
            "5E/vBjg6TQolumVqtoZfNoLkojYDEu6LRDKllpWpyPsq6chKMpmDeU1waWTgtWQi\n" +
            "N44VUSGO0kXGaaKilhQHWuS3JLG5DTMW1HEl8qlUz9y4akXU/4diA7pkUyDGSwS7\n" +
            "qwIDAQAB\n" +
            "-----END PUBLIC KEY-----")

    val sign = Base64Utils.decodeFromString("pz/fXV7UGMYF0xpdbiRC4H2p8x6k9g1B+3taF3ZTMidcJMtx/zPJOXXxEA+SCBv0j6Nc0aYg/V1hKBdYaxxfQM6UqLOVmczbgbCj2aDQAD6N9kAwuIDKsLzm45FRuT4N3qxDT+SVSHnrZKFGtbRRnJFawyKb2ed2LXQmNFdftJIOWv+DQaCMBwCGwpmxYJTDP5sG83T5fJkJHejTgAfUvUwJeANScudsOB3ih1H1TBQdyY8qBPkJNH9k+S6MC1sSQIGNL8D2114vmgNSNTW/uQfNxYFk8FaSy4d9uLSYdCTRovVS9hsQyuE6zufujnt+853Vrf4vCTcEWXkf00g1ww==")
    v.verify("balabalabalabala".toByteArray(Charsets.UTF_8), sign)

    SpringApplication.run(DummyAuthServer::class.java, *args)
}