dependencies {
    api("com.labijie.infra:commons:${Versions.infraCommons}")
    api("org.springframework.boot:spring-boot-starter-web")
//    api 'javax.xml.bind:jaxb-api'
//    api 'com.sun.xml.bind:jaxb-core'
//    api 'com.sun.xml.bind:jaxb-impl'
//    api("com.nimbusds:nimbus-jose-jwt:$nimbus_jose_jwt_version")

//    api "org.springframework.security:spring-security-oauth2-core: $spring_security_version"
    api("org.springframework.security:spring-security-core")
    api("com.nimbusds:oauth2-oidc-sdk:${Versions.oauth2OidcSdk}")
}