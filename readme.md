# 基础组件包

![maven central version](https://img.shields.io/maven-central/v/com.labijie.infra/oauth2-starter?style=flat-square)
![workflow status](https://img.shields.io/github/workflow/status/hongque-pro/infra-oauth2/Gradle%20Build%20And%20Release?label=CI%20publish&style=flat-square)
![license](https://img.shields.io/github/license/hongque-pro/infra-oauth2?style=flat-square)

## 新版本 1.1.0 破坏性变化（breaking changes） :

- 完全兼容 Spring security 5.4.x
- 使用方式由原来的注解变为 ” starter" + 配置。
- Spring Cloud OAuth2 被移除（官方不再支持）
- EnableResourceServer 的方式被移除（官方不再支持）

> Spring Security 5.4 带来大量破坏性变化（程序中大量的类已经被标记为过时），使得该项目不得不跟随变化

**Spring Security 5.4.6** 已经**弃用**spring cloud oauth2 和以前的 spring security oauth2, 具体对比参考这个文档:   
https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Features-Matrix


Spring 官方迁移说明：   
https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide

新版 Spring Security Resource Server 文档:   
https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2   

> 注意，该项目仅支持 servlet 应用，webflux 不提供支持

## 如何实现一个 OAuth2 授权服务器？
屏蔽所有复杂的细节，当你需要一个OAuth2 授权服务器时，你只需要三个步骤：

【1】 引入依赖
```groovy
    compile "com.labijie.infra:oauth2-auth-server-starter:$infra_oauth2_version"
```
【2】实现 **IIdentityService** 接口作为一个 Bean 注册给 Spring   

【3】 实现 **IClientDetailsServiceFactory** 接口作为一个 Bean 注册给 Spring   


## 如何实现一个使用上面的 OAuth2 授权服务器授权的资源服务器？
引入依赖包即可：

```groovy
    compile "com.labijie.infra:oauth2-resource-server-starter:$infra_oauth2_version"
```


## 如何是一个OAuth2 服务器同时本身又包含需要授权的资源？   
授权服务器项目包含资源服务器依赖包即可！

## 灵活切换 JWT, Memory, Redis 的 OAuth2 Token 存储实现：
使用配置 （ store 配置可用值：Jwt,  InMemory, Redis, 默认未 Jwt）：   
```yaml
infra:
  oauth2:
    token:
      store: InMemory 
```

> 注意 redis 需要自己引入 Spring 官方的 **spring-boot-starter-data-redis** 包

## 如何实现真正的两段身份验证？

> 2FAC 逻辑：可以强制用户必须两端认证登录，先输入用户名、密码，获得一般权限 token (1段 Token);
> 验证通过可以有限的访问资源，一些敏感资源，如取现接口、删除数据接口要求用户使用1段 token 以短信、邮件等方式来交换2段 token 以获得无限制的访问权限。

扩展 Spring 加入 **twoFactorRequired** 方法：
```kotlin
class ResourceServerConfigurer : ResourceServerConfigurerAdapter() {
    override fun configure(resources: ResourceServerSecurityConfigurer) {
        resources.resourceId("test")
    }

    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http.requestMatchers().anyRequest()
                .and()
                .anonymous()
                .and()
                .authorizeRequests()
                .antMatchers("/2f").twoFactorRequired()
                .antMatchers("/**").authenticated()
    }
}
```

## 更多能力

- 实现 Token 中插入自定义字段，直接通过 token 访问该字段以减少数据库查询：
```kotlin
interface IIdentityService {

    val customPasswordChecks: Boolean
        get() = false

    @Throws(UsernameNotFoundException::class, InternalAuthenticationServiceException::class)
    fun getUserByName(userName: String): ITwoFactorUserDetails

    fun authenticationChecks(authenticationCheckingContext: AuthenticationCheckingContext): SignInResult
}
```   
上面的 **IIdentityService** 接口中 getUserByName 实现的返回值未 **ITwoFactorUserDetails**,  ITwoFactorUserDetails 的 getTokenAttributes 返回的 Map 对象会放入 Token 中。

字符串的自定义字段还支持 spring security 验证

```kotlin
registry
         .mvcMatchers("/test/field-aaa-test").hasTokenAttributeValue("aaa", "test")
```

上述规则要求 token 中必须包含 aaa 属性，同时值必须是 test 。

## 开发环境兼容性：

|组件|版本|说明|
|--------|--------|--------|
|   kotlin    |      1.4.10    |           |
|   jdk    |      1.8   |           |
|   spring boot    |      2.4.5    |           |
|   spring security    |     5.4.6    |      Spring 版本重大变化     |
|   spring framework    |      5.3.6   |           |
|   spring dpendency management    |      1.0.10.RELEASE    |           |

## 发布到自己的 Nexus

在项目根目录下新建 gradle.properties 文件，添加如下内容

```text
PUB_USER=[nexus user name]
PUB_PWD=[nexus password]
PUB_URL=http://XXXXXXX/repository/maven-releases/
```
运行  **gradle publish**
