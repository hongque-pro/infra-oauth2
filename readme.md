# 基础组件包

![maven central version](https://img.shields.io/maven-central/v/com.labijie.infra/oauth2-commons?logo=java)
![workflow status](https://img.shields.io/github/actions/workflow/status/hongque-pro/infra-oauth2/build.yml?branch=main)
![license](https://img.shields.io/github/license/hongque-pro/infra-oauth2?style=flat-square)
![Static Badge](https://img.shields.io/badge/GraalVM-supported-green?style=flat&logoColor=blue&labelColor=orange)

基于 [**Spring-Authorization-Server**](https://github.com/spring-projects/spring-authorization-server)  的 OAuth2 服务器扩展。 
频闭 Spring Security 和 Spring Authorization Server 复杂性，专注于业务。

> 注意，该项目仅支持 servlet 应用，webflux 不提供支持

## 如何实现一个 OAuth2 授权服务器？
屏蔽所有复杂的细节，当你需要一个OAuth2 授权服务器时，你只需要三个步骤：

【1】 引入依赖
```groovy
    compile "oauth2-authorization-server-starter:<your version>"
```
【2】实现 **IIdentityService** 接口作为一个 Bean 注册给 Spring    
【3】配置 RSA 密钥用于 JWT 加密
```yaml
infra:
  oauth2:
    token:
      jwt:
        rsa:
          private-key: <private_key>
          public-key: <publick_key>
```
:bell:**注意**：为方便开发起见，程序中内置了 RSA 密钥对，如果不配置将使用默认密钥对，生产环境请自行生成密钥对，否则将有安全隐患。
>授权服务器默认将在 **/oauth/.well-known/jwks.json** 路径上暴露 JWK 公钥信息。

## 如何实现一个使用上面的 OAuth2 授权服务器授权的资源服务器？
引入依赖包即可：

```groovy
    compile "com.labijie.infra:oauth2-resource-server-starter:<your version>"
```

资源服务器的本质就是验证由授权服务器颁发的 token，来确定是否响应用户请求，有两种方式验证 jwt token:

**A. [JWT](https://datatracker.ietf.org/doc/html/rfc7519), 即使用一个 RSA 公钥验证 token**   
通过公钥来验证 jwt token, 有三种方式配置公钥:

【1】 直接配置一个 RSA 公钥：
```yaml
infra.oauth2.resource-server.jwt.rsa-pub-key=<RSA_PUBLICK_KEY>
```
或者
```kotlin
spring.security.oauth2.resourceserver.jwt.public-key-location=<public-key>
```
使用 `infra.oauth2.resource-server.jwt.rsa-pub-key`  的好处是同时支持本地文件路径、公钥内容和资源文件路径。

【2】 从授权服务器获取公开的 RSA 公钥：   
这种方式，资源服务器无需关心 RSA 公钥，公钥从授权服务器获取。
```yaml
spring.security.oauth2.resourceserver.jwt.jwk-set-uri=<JWK_URI>
```
其中 **JWK_URI** 是授权服务器暴露的 JWK 终结点，默认为 `/oauth2/jwks`。  

:bell:如果以上三项配置均未找到，将使用默认内置的 RSA 公钥，生产环境请自行配置，否则可能造成安全隐患。  

**B. [自省 Token 端点](https://datatracker.ietf.org/doc/html/rfc7662)**   
通常，大多数服务器都使用 JWT （即 RSA 公钥验证）来验证请求的 token， 也有一些服务器使用 `opaque token` , 这些 token 对 resource server 不透明，只
能通过授权服务器自省， **自省**,本质上就是拿着 token 调用一个授权服务器的接口来验证 token 有效性。    
   
Spring Auth Server 同时支持 JWK 和 自省，可以根据需求进行选择。
> - 自省无需在资源服务器上分发 RSA 公钥， 但是，授权服务器需要接受来自资源服务器的验证请求，这将增加授权服务器的压力。   
> - 出于性能考虑，还是推荐分发公钥到资源服务器来分摊 token 验证压力。   
> - 自省要求资源服务器提供 OAuth2 client 的 client id 和 client secret。

通过 Spring 提供的配置来配置自省：

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        opaquetoken:
          client-id: <client id>
          client-secret: <client secret>
          introspection-uri: http://your-auth-server/oauth2/introspect
```

授权服务器默认暴露的自省终结点为： `/oauth2/introspect`


> 注意，不论是授权服务器还是资源服务器，都需要自己注解 **EnableWebSecurity** 到你的工程。

## 如何是一个OAuth2 服务器同时本身又包含需要授权的资源？   
授权服务器项目包含资源服务器依赖包即可！

## 配置 OAuth2AuthorizationService (用于存储 Oauth2 Token )
application.yml 中加入以下配置: 
```yaml
infra:
  oauth2:
    authorization-service:
      provider: jdbc
```
支持三种 OAuth2AuthorizationService (通过 provider 配置)

- caching（**默认值**）: [**caching-kotlin**](https://github.com/endink/caching-kotlin) 存储 token
- jdbc: 官方 jdbc 实现
- memory: 官方 in memory 实现

> 注意配置 caching 需要自己引入下列包之一： 
> 
> **com.labijie:caching-kotlin-core-starter**   
> **com.labijie:caching-kotlin-redis-starter**   
> 
> 具体参考 [**caching-kotlin**](https://github.com/endink/caching-kotlin) 项目。

## 如何实现真正的两段身份验证？

> 2FAC 逻辑：可以强制用户必须两端认证登录，先输入用户名、密码，获得一般权限 token (1段 Token);
> 验证通过可以有限的访问资源，一些敏感资源，如取现接口、删除数据接口要求用户使用1段 token 以短信、邮件等方式来交换2段 token 以获得无限制的访问权限。

扩展 Spring 加入 **twoFactorRequired** 方法：
```kotlin
class ResourceServerConfigurer : IResourceAuthorizationConfigurer {
  
    @Throws(Exception::class)
    override fun configure(registry: ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry) {
        registry.mvcMatchers("/2f").twoFactorRequired()
        registry.mvcMatchers("/other").twoFactorRequired()
    }
}
```
> 使用 **IResourceAuthorizationConfigurer** 接口可以避免 SecurityFilterChain 顺序问题。

## 更多能力
- Cookie 支持 （支持通过一个自定义 token 携带 Bearer Token）
```yaml
infra:
  oauth2:
    resource-server:
      bearer-token-resolver:
        allow-cookie-name: "OAuth2Token"
```
> 当 `allow-cookie-name` 为空（默认）时，表示不支持 cookie 授权。

- 实现 Token 中插入自定义字段，直接通过 token 访问该字段以减少数据库查询：
```kotlin
interface IIdentityService {
    fun getUserByName(userName: String): ITwoFactorUserDetails
}
```   
上面的 `IIdentityService` 接口中 `getUserByName` 实现的返回值为 **ITwoFactorUserDetails**,
`ITwoFactorUserDetails` 的 `getTokenAttributes` 返回的 Map 对象会放入 Token 中。

*字符串的自定义字段还支持 spring security 验证*

```kotlin
registry.mvcMatchers("/test/field-aaa-test").hasTokenAttributeValue("aaa", "test")
```

上述规则要求 token 中必须包含 aaa 属性，同时值必须是 test 。

