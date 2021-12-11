# 基础组件包

![maven central version](https://img.shields.io/maven-central/v/com.labijie.infra/oauth2-auth-server-starter?style=flat-square)
![workflow status](https://img.shields.io/github/workflow/status/hongque-pro/infra-oauth2/Gradle%20Build%20And%20Release?label=CI%20publish&style=flat-square)
![license](https://img.shields.io/github/license/hongque-pro/infra-oauth2?style=flat-square)

## 1.2.x Break Changes 

- 移除 Spring Security OAuth 2。
- 移除 Spring Cloud OAuth2 。
- 不再支持 TOKEN STORE 配置 token 存储， 仅支持 JWT 。
- 不再依赖 spring data redis ， 默认使用 [caching-kotlin](https://github.com/endink/caching-kotlin) 存储 token。
- 集成 [spring-authorization-server](https://github.com/spring-projects/spring-authorization-server)。
- 兼容原有的 Password Grant Type。
- 不再需要 IClientDetailsServiceFactory 实现。
- 包名由 oauth2-auth-server-starter 变更为 **oauth2-authorization-server-starter**

> **spring-authorization-server** 原生不支持 password GrantType，该授权方式已经在 Oauth2.1 被移除，官方暂无支持计划，具体请看:   
> https://github.com/spring-projects/spring-authorization-server/issues/349   
> *该项目通过扩展 spring-authorization-server 已经实现，完全兼容原有的 password 模式*。

**Spring Security 5.4.6** 已经**弃用**spring cloud oauth2 和以前的 spring security oauth2, 具体对比参考这个文档:   
https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Features-Matrix


Spring 官方迁移说明：   
https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide

新版 Spring Security Resource Server 文档:   
https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html

> 注意，该项目仅支持 servlet 应用，webflux 不提供支持

## 如何实现一个 OAuth2 授权服务器？
屏蔽所有复杂的细节，当你需要一个OAuth2 授权服务器时，你只需要三个步骤：

【1】 引入依赖
```groovy
    compile "oauth2-authorization-server-starter:<your version>"
```
【2】实现 **IIdentityService** 接口作为一个 Bean 注册给 Spring    


## 如何实现一个使用上面的 OAuth2 授权服务器授权的资源服务器？
引入依赖包即可：

```groovy
    compile "com.labijie.infra:oauth2-resource-server-starter:<your version>"
```

> 注意，不论是授权服务器还是资源服务器，都需要自己注解 **EnableWebSecurity** 到你的工程。

## 如何是一个OAuth2 服务器同时本身又包含需要授权的资源？   
授权服务器项目包含资源服务器依赖包即可！

## 配置 OAuth2AuthorizationService (用于存储 Oauth2 Token )
使用配置 （ store 配置可用值：Jwt,  InMemory, Redis, 默认未 Jwt）：   
```yaml
infra:
  oauth2:
    authorization-service: jdbc
```
支持三种 OAuth2AuthorizationService

- caching（**默认值**）: [caching-kotlin](https://github.com/endink/caching-kotlin) 存储 token
- jdbc: 官方 jdbc 实现
- memory: 官方 in memory 实现

> 注意 redis 需要自己引入 Spring 官方的 **spring-boot-starter-data-redis** 包

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

- 实现 Token 中插入自定义字段，直接通过 token 访问该字段以减少数据库查询：
```kotlin
interface IIdentityService {
    fun getUserByName(userName: String): ITwoFactorUserDetails
}
```   
上面的 **IIdentityService** 接口中 getUserByName 实现的返回值为 **ITwoFactorUserDetails**,
ITwoFactorUserDetails 的 getTokenAttributes 返回的 Map 对象会放入 Token 中。

*字符串的自定义字段还支持 spring security 验证*

```kotlin
registry.mvcMatchers("/test/field-aaa-test").hasTokenAttributeValue("aaa", "test")
```

上述规则要求 token 中必须包含 aaa 属性，同时值必须是 test 。

