# 基础组件包

![maven central version](https://img.shields.io/maven-central/v/com.labijie.infra/oauth2-starter?style=flat-square)
![workflow status](https://img.shields.io/github/workflow/status/hongque-pro/infra-oauth2/Gradle%20Build%20And%20Release?label=CI%20publish&style=flat-square)
![license](https://img.shields.io/github/license/hongque-pro/infra-oauth2?style=flat-square)

完全兼容 Spring security 5.4.x

>> Spring security break changes:    
>>  https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2

## 引入依赖（Gradle）

```groovy
    compile "com.labijie.infra:oauth2-starter:$infra_oauth2_version"
```

扩展 Spring Cloud OAuth2 能力，极大的简化 Spring Security 使用。

## 如何实现一个 OAuth2 授权服务器？
屏蔽所有复杂的细节，当你需要一个OAuth2 服务器时，你只需要三个步骤：

1. 实现 **IIdentityService** 接口作为一个 Bean 注册给 Spring
2. 实现 **IClientDetailsServiceFactory** 接口作为一个 Bean 注册给 Spring
3. 在你的启动程序注解 @EnableOAuth2Server, 如下：

```kotlin
@EnableOAuth2Server(OAuth2ServerType.Authorization)
@SpringBootApplication
class DummyAuthServer
```

## 如何实现一个使用上面的 OAuth2 授权服务器授权的资源服务器？
在你的启动程序注解 @EnableOAuth2Server, 如下：
```kotlin
@EnableOAuth2Server(OAuth2ServerType.Resource)
@SpringBootApplication
class DummyResourceServer
```

## 如何是一个OAuth2 服务器同时本身又包含需要授权的资源？
参见 OAuth2 授权服务器实现步骤 1、 2 ， 在第 3 步时稍微改一下注解：

```kotlin
@EnableOAuth2Server(OAuth2ServerType.Authorization, OAuth2ServerType.Resource)
@SpringBootApplication
class DummyAuthServer
```

## 灵活切换 JWT, Memory, Redis 的 OAuth2 Token 存储实现：
- Jwt:
```kotlin
@EnableOAuth2Server(OAuth2ServerType.Authorization, tokeStore = TokenStoreType.Jwt)
class DummyAuthServer
```
> Jwt 是默认实现，可以省略 **tokeStore** 参数
- InMemory:
```kotlin
@EnableOAuth2Server(OAuth2ServerType.Authorization, tokeStore = TokenStoreType.InMemory)
class DummyAuthServer
```
- Redis:
```kotlin
@EnableOAuth2Server(OAuth2ServerType.Authorization, tokeStore = TokenStoreType.Redis)
class DummyAuthServer
```

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

- 同一个接口即可实现 Token 中插入自定义字段，直接通过 token 访问该字段以减少数据库查询
- Resource Token 缓存，减少和 OAuth 服务器的交互（oauth2-resource-token-starter）

## 开发环境兼容性：

|组件|版本|说明|
|--------|--------|--------|
|   kotlin    |      1.4.10    |           |
|   jdk    |      1.8   |           |
|   spring boot    |      2.3.4.RELEASE    |           |
|  spring cloud    |      Hoxton.SR8    |   通过 BOM 控制版本，因为 cloud 组件版本混乱，无法统一指定  |
|   spring framework    |      5.2.9.RELEASE   |           |
|   spring dpendency management    |      1.0.10.RELEASE    |           |

## 发布到自己的 Nexus

在项目根目录下新建 gradle.properties 文件，添加如下内容

```text
PUB_USER=[nexus user name]
PUB_PWD=[nexus password]
PUB_URL=http://XXXXXXX/repository/maven-releases/
```
运行  **gradle publish**
