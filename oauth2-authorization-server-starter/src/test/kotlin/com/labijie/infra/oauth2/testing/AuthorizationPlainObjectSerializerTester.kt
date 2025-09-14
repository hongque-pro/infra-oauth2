package com.labijie.infra.oauth2.testing

import com.labijie.infra.json.JacksonHelper
import com.labijie.infra.oauth2.AccessTokenPlainObject
import com.labijie.infra.oauth2.AuthorizationPlainObject
import com.labijie.infra.oauth2.AuthorizationSerializableObject
import com.labijie.infra.oauth2.AuthorizationSerializableObject.Companion.asPlain
import com.labijie.infra.oauth2.AuthorizationSerializableObject.Companion.asSerializable
import com.labijie.infra.oauth2.MetadataType
import com.labijie.infra.oauth2.MetadataTypedValue
import com.labijie.infra.oauth2.MetadataTypedValue.Companion.toMetadataValue
import com.labijie.infra.oauth2.TokenPlainObject
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import java.net.URI
import java.net.URL
import java.time.Duration
import java.time.Instant
import java.time.LocalDateTime
import java.util.Locale
import java.util.UUID
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/6/30
 *
 */

@OptIn(ExperimentalSerializationApi::class)
class AuthorizationPlainObjectSerializerTester {

    companion object {
        fun randomAuthorizationPlainObject(): AuthorizationPlainObject {
            fun randomString(length: Int = 16): String {
                val chars = ('a'..'z') + ('A'..'Z') + ('0'..'9')
                return (1..length)
                    .map { chars.random() }
                    .joinToString("")
            }

            fun randomStringSet(length: Int = 16): Set<String> {
                return (1..length)
                    .map { UUID.randomUUID().toString() }
                    .toSet()
            }

            fun randomByteArray(size: Int = 32): ByteArray =
                ByteArray(size) { Random.nextInt(0, 256).toByte() }

            fun randomEpochSecondOffset(base: Long = Instant.now().epochSecond): Long =
                base + Random.nextLong(-3600, 3600 * 24 * 7) // +/- 1 hour to 7 days


            fun generateValueForType(type: MetadataType): Any = when (type) {
                MetadataType.ByteArray -> Random.nextBytes(Random.nextInt(4, 16))
                MetadataType.String -> randomString(Random.nextInt(5, 15))
                MetadataType.Int -> Random.nextInt(0, 10000)
                MetadataType.Long -> Random.nextLong(0, 1_000_000)
                MetadataType.Instant -> Instant.now().minusSeconds(Random.nextLong(0, 100000))
                MetadataType.LocalDateTime -> LocalDateTime.now().minusMinutes(Random.nextLong(0, 10000))
                MetadataType.Duration -> Duration.ofMillis(Random.nextLong(1000, 60_000))
                MetadataType.Locale -> Locale.forLanguageTag(listOf("en-US", "zh-CN", "fr-FR", "ja-JP").random())
                MetadataType.URL -> URL.of(URI("https://example.com/${randomString(5)}"), null)
                MetadataType.URI -> URI("urn:example:${randomString(5)}")
                MetadataType.UUID -> UUID.randomUUID()
                MetadataType.Boolean -> Random.nextBoolean()
                else -> throw IllegalArgumentException("Unsupported type: $type")
            }

            fun randomMetadataMap(count: Int): Map<String, MetadataTypedValue> {
                val types = MetadataType.entries.filter { it != MetadataType.Unknown }
                val map = mutableMapOf<String, MetadataTypedValue>()

                repeat(count) {
                    val key = "key_${randomString(6)}"
                    val type = types.random()
                    val value = generateValueForType(type)
                    map[key] = value.toMetadataValue()
                }

                return map
            }

            fun randomToken(): TokenPlainObject {
                return TokenPlainObject().apply {
                    tokenValue = randomString(32)
                    issuedAtEpochSecond = Instant.now().epochSecond - Random.nextLong(0, 3600)
                    expiresAtEpochSecond = issuedAtEpochSecond!! + Random.nextLong(600, 3600 * 24)
                    claims = randomMetadataMap(16)
                    invalidated = Random.nextBoolean()
                }
            }



            fun randomAccessToken(): AccessTokenPlainObject {
                return AccessTokenPlainObject().apply {
                    tokenValue = randomString(32)
                    issuedAtEpochSecond = Instant.now().epochSecond - Random.nextLong(0, 3600)
                    expiresAtEpochSecond = issuedAtEpochSecond!! + Random.nextLong(600, 3600 * 24)
                    claims = randomMetadataMap(16)
                    tokenType = listOf("Bearer", "MAC").random()
                    scopes = arrayOf("read", "write", "delete").apply { shuffle() }.take(Random.nextInt(1, 3)).toTypedArray()
                    invalidated = Random.nextBoolean()
                }
            }

            return AuthorizationPlainObject().apply {
                id = randomString(12)
                clientId = randomString(10)
                principalName = "user_${randomString(6)}"
                grantType = listOf("authorization_code", "client_credentials", "password").random()
                scopes = if (Random.nextBoolean()) randomStringSet(16).toHashSet() else hashSetOf()
                state = if (Random.nextBoolean()) randomString(8) else null
                authorizationCodeToken = if (Random.nextBoolean()) randomToken() else null
                accessToken = if (Random.nextBoolean()) randomAccessToken() else null
                oidcIdToken = if (Random.nextBoolean()) randomToken() else null
                refreshToken = if (Random.nextBoolean()) randomToken() else null
            }
        }
    }


    @Test
    fun testProtobuf() {

        repeat(10) {
            val obj = randomAuthorizationPlainObject()

            val byteArray = ProtoBuf.encodeToByteArray(obj.asSerializable())
            val obj2 = ProtoBuf.decodeFromByteArray<AuthorizationSerializableObject>(byteArray).asPlain()

            assert(obj !== obj2)
            assert(obj == obj2) {
                """
                    Not equals:
                    ${JacksonHelper.serializeAsString(obj)}
                    
                    ${JacksonHelper.serializeAsString(obj2)}
                """.trimIndent()
            }
        }
    }
}