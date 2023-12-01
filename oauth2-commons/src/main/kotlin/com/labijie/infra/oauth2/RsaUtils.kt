package com.labijie.infra.oauth2

import org.springframework.util.Base64Utils
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*


/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-02-23
 */
object RsaUtils {

    fun getPublicKey(key: String): RSAPublicKey {
        val keyValue = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
        val keyBytes: ByteArray = Base64.getMimeDecoder().decode(keyValue)
        val keySpec = X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePublic(keySpec) as RSAPublicKey
    }


    fun getPrivateKey(key: String): RSAPrivateKey {
        val keyValue = key.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")
        val keyBytes: ByteArray = Base64.getMimeDecoder().decode(keyValue)
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePrivate(keySpec) as RSAPrivateKey
    }

    val defaultKeyPair: KeyPair by lazy {
        try {
            val privateExponent = "3851612021791312596791631935569878540203393691253311342052463788814433805390794604753109719790052408607029530149004451377846406736413270923596916756321977922303381344613407820854322190592787335193581632323728135479679928871596911841005827348430783250026013354350760878678723915119966019947072651782000702927096735228356171563532131162414366310012554312756036441054404004920678199077822575051043273088621405687950081861819700809912238863867947415641838115425624808671834312114785499017269379478439158796130804789241476050832773822038351367878951389438751088021113551495469440016698505614123035099067172660197922333993"
            val modulus = "18044398961479537755088511127417480155072543594514852056908450877656126120801808993616738273349107491806340290040410660515399239279742407357192875363433659810851147557504389760192273458065587503508596714389889971758652047927503525007076910925306186421971180013159326306810174367375596043267660331677530921991343349336096643043840224352451615452251387611820750171352353189973315443889352557807329336576421211370350554195530374360110583327093711721857129170040527236951522127488980970085401773781530555922385755722534685479501240842392531455355164896023070459024737908929308707435474197069199421373363801477026083786683"
            val exponent = "65537"
            val publicSpec = RSAPublicKeySpec(BigInteger(modulus), BigInteger(exponent))
            val privateSpec = RSAPrivateKeySpec(BigInteger(modulus), BigInteger(privateExponent))
            val factory: KeyFactory = KeyFactory.getInstance("RSA")
            KeyPair(factory.generatePublic(publicSpec), factory.generatePrivate(privateSpec))
        } catch (e: Exception) {
            throw IllegalArgumentException(e)
        }
    }
}
