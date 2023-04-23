```xml
<!--  shiro坐标      -->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.3.2</version>
</dependency>
```

## 1 什么是Shiro

Apache Shiro是一个强大且易用的Java安全框架,执行身份验证、授权、密码和会话管理。使用Shiro的易于理解的 API,您可以快速、轻松地获得任何应用程序,从最小的移动应用程序到最大的网络和企业应用程序。

### 1.2 与Spring Security的对比

 Shiro：

 Shiro较之 Spring Security，Shiro在保持强大功能的同时，还在简单性和灵活性方面拥有巨大优势。

1. 易于理解的 Java Security API；

2.   简单的身份认证（登录），支持多种数据源（LDAP，JDBC，Kerberos，ActiveDirectory 等）；

3. 对角色的简单的签权（访问控制），支持细粒度的签权；

4. 支持一级缓存，以提升应用程序的性能； 

5. 内置的基于 POJO 企业会话管理，适用于 Web 以及非 Web 的环境；

6. 异构客户端会话访问； 

7.  非常简单的加密 API； 

8. 不跟任何的框架或者容器捆绑，可以独立运行 

   

   Spring Security： 

   除了不能脱离Spring，shiro的功能它都有。而且Spring Security对Oauth、OpenID也有支持,Shiro则需要自己手 动实现。Spring Security的权限细粒度更高。

   

   ### 1.3 Shiro的功能模块

Shiro可以非常容易的开发出足够好的应用，其不仅可以用在JavaSE环境，也可以用在JavaEE环境。Shiro可以帮助 我们完成：认证、授权、加密、会话管理、与Web集成、缓存等。这不就是我们想要的嘛，而且Shiro的API也是非 常简单；其基本功能点如下图所示：

![![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.2e00q89jvfdw.webp)](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.8l3f7b03ho8.webp)

![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.2e00q89jvfdw.webp)



## 2 Shiro的内部结构

![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.6gk0m012jx80.webp)

![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.ytuuwsgkj0g.webp)

## 3 应用程序使用Shiro

![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.5w2mbkzdu3o0.webp)

# 4 springBoot整合shiro

使用springBoot构建应用程序，整合shiro框架完成用户认证与授权。

## 4.1 数据库表

![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.4bhaujmnqfs0.png)

### 4.1.1整合依赖

```xml
<!--shiro和spring整合-->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring</artifactId>
    <version>1.3.2</version>
</dependency>
<!--shiro核心包-->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.3.2</version>
</dependency>
<!--shiro与redis整合-->
<dependency>
    <groupId>org.crazycake</groupId>
    <artifactId>shiro-redis</artifactId>
    <version>3.0.0</version>
</dependency>
```



### 4.1.2 修改登录方法

```java
//用户登录
@RequestMapping(value="/login")
   public String login(String username,String password) {
    //构造登录令牌
       try {

           /**
            * 密码加密：
            *     shiro提供的md5加密
            *     Md5Hash:
            *      参数一：加密的内容
            *              111111   --- abcd
            *      参数二：盐（加密的混淆字符串）（用户登录的用户名）
            *              111111+混淆字符串
            *      参数三：加密次数
            *
            */
           password = new Md5Hash(password,username,3).toString();

           UsernamePasswordToken upToken = new UsernamePasswordToken(username,password);
           //1.获取subject
           Subject subject = SecurityUtils.getSubject();
               
           //获取session
           String sid = (String) subject.getSession().getId();

           //2.调用subject进行登录
           subject.login(upToken);
           return "登录成功";
       }catch (Exception e) {
           return "用户名或密码错误";
       }
   }
```

### 4.1.3 自定义realm

```java
/**
 * 自定义的realm
 */
public class CustomRealm extends AuthorizingRealm {

    public void setName(String name) {
        super.setName("customRealm");
    }

    @Autowired
    private UserService userService;

    /**
     * 授权方法
     *      操作的时候，判断用户是否具有响应的权限
     *          先认证 -- 安全数据
     *          再授权 -- 根据安全数据获取用户具有的所有操作权限
     *
     *
     */
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //1.获取已认证的用户数据
        User user = (User) principalCollection.getPrimaryPrincipal();//得到唯一的安全数据
        //2.根据用户数据获取用户的权限信息（所有角色，所有权限）
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        Set<String> roles = new HashSet<>();//所有角色
        Set<String> perms = new HashSet<>();//所有权限
        for (Role role : user.getRoles()) {
            roles.add(role.getName());
            for (Permission perm : role.getPermissions()) {
                perms.add(perm.getCode());
            }
        }
        info.setStringPermissions(perms);
        info.setRoles(roles);
        return info;
    }


    /**
     * 认证方法
     *  参数：传递的用户名密码
     */
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //1.获取登录的用户名密码（token）
        UsernamePasswordToken upToken = (UsernamePasswordToken) authenticationToken;
        String username = upToken.getUsername();
        String password = new String( upToken.getPassword());
        //2.根据用户名查询数据库
        User user = userService.findByName(username);
        //3.判断用户是否存在或者密码是否一致
        if(user != null && user.getPassword().equals(password)) {
            //4.如果一致返回安全数据
            //构造方法：安全数据，密码，realm域名
            SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(user,user.getPassword(),this.getName());
            return info;
        }
        //5.不一致，返回null（抛出异常）
        return null;
    }
```

### 4.1.4  Shiro配置

```java
package cn.axing.shiro;

import cn.axing.shiro.realm.CustomRealm;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.apache.shiro.mgt.SecurityManager;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author axing
 * @version 1.0.0
 * @description ShiroConfiguration配置类
 * @date 2023/4/23 14:21
 */

@Configuration
public class ShiroConfiguration {

    //1、创建realm
    @Bean
    public CustomRealm getRealm(){
        return new CustomRealm();
    }

    //2、创建安全管理器
    @Bean
    public SecurityManager getSecurityManager(CustomRealm realm) {
     DefaultWebSecurityManager SecurityManager = new DefaultWebSecurityManager();
        SecurityManager.setRealm(realm);
        return SecurityManager;
    }

    //3、配置shiro过滤器工厂
    
    /*
         web程序中，shiro进行权限控制需要通过过滤器集合进行控制
     */
    //Filter工厂，设置对应的过滤条件和跳转条件
    @Bean
    public ShiroFilterFactoryBean shirFilter(SecurityManager securityManager) {
        //1.创建shiro过滤器工厂
        ShiroFilterFactoryBean filterFactory = new ShiroFilterFactoryBean();
        //2.设置安全管理器
        filterFactory.setSecurityManager(securityManager);
        //3.通用配置（配置登录页面，登录成功页面，验证未成功页面）
        filterFactory.setLoginUrl("/autherror?code=1"); //设置登录页面
        filterFactory.setUnauthorizedUrl("/autherror?code=2"); //授权失败跳转页面
        //4.配置过滤器集合
        /**
         * key ：访问连接
         *     支持通配符的形式
         * value：过滤器类型
         *     shiro常用过滤器
         *         anno   ：匿名访问（表明此链接所有人可以访问）
         *         authc   ：认证后访问（表明此链接需登录认证成功之后可以访问）
         */
        Map<String,String> filterMap = new LinkedHashMap<String,String>();
        //filterMap.put("/user/home","anon");//当前请求地址可以匿名访问

        //具有某中权限才能访问
        //使用过滤器的形式配置请求地址的依赖权限
        //filterMap.put("/user/home","perms[user-home]"); //不具备指定的权限，跳转到setUnauthorizedUrl地址

        //使用过滤器的形式配置请求地址的依赖角色
       // filterMap.put("/user/home","roles[系统管理员]");
        filterMap.put("/user/**", "authc");

        //5.设置过滤器
        filterFactory.setFilterChainDefinitionMap(filterMap);
        return filterFactory;
    }

        //4、开启对shiro的注解支持
        @Bean
        public AuthorizationAttributeSourceAdvisor
        authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
            AuthorizationAttributeSourceAdvisor advisor = new
                    AuthorizationAttributeSourceAdvisor();
            advisor.setSecurityManager(securityManager);
            return advisor;
        }
}
```

### 4.1.5   shiro中的过滤器

![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.47mkcyzr3co0.jpg)

## 4.2 授权

###  4.2.1 基于配置的授权

```java
//配置请求连接过滤器配置
//匿名访问（所有人员可以使用）
        filterMap.put("/user/home", "anon");
                //具有指定权限访问
                filterMap.put("/user/find", "perms[user-find]");
                //认证之后访问（登录之后可以访问）
                filterMap.put("/user/**", "authc");
                //具有指定角色可以访问
                filterMap.put("/user/**", "roles[系统管理员]");
```



### 4.2.2  基于注解的授权

(1)RequiresPermissions

配置到方法上，表明执行此方法必须具有指定的权限

```java
//查询
@RequiresPermissions(value = "user-find")
public String find() {
        return "查询用户成功";
        }
```

（2）RequiresRoles

配置到方法上，表明执行此方法必须具有指定的角色

```java
//查询
@RequiresRoles(value = "系统管理员")
public String find() {
    return "查询用户成功";
}
```

基于注解的配置方式进行授权，一旦操作用户不具备操作权限，目标方法不会被执行，而且会抛出 AuthorizationException 异常。所以需要做好统一异常处理完成未授权处理



# 5 Shiro中的会话管理

![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.669ast8fzfg0.jpg)

##### SessionManager（会话管理器）：

 管理所有Subject的session包括创建、维护、删除、失效、验证等工作。SessionManager是顶层组件，由SecurityManager管理
shiro提供了三个默认实现:

1.DefaultSessionManager:用于JavaSE环境

2.ServletContainerSessionManager : 用于Web环境，直接使用servlet容器的会话.

3.DefaultWebSessionManager: 用于web环境，自己维护会话(自己维护着会话，直接废弃了Servlet容器的会话管理 )。
	在web程序中，通过shiro的Subiect.login0方法登录成功后，用户的认证信息实际上是保存在HttpSession中的通过如下代码验证。


​        

#####  应用场景分析

 在分布式系统或者微服务架构下，都是通过统一的认证中心进行用户认证。如果使用默认会话管理，用户信息只会 保存到一台服务器上。那么其他服务就需要进行会话的同步

![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.6cpyxpdfqpg0.jpg)

会话管理器可以指定sessionId的生成以及获取方式。 

通过sessionDao完成模拟session存入，取出等操作

## 4.1 Shiro结合redis的统一会话管理

![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.6z5h1z9kc640.jpg)

##### （1）构建环境

（1）使用开源组件Shiro-Redis可以方便的构建shiro与redis的整合工程。

```xml
<dependency>
<groupId>org.crazycake</groupId>
<artifactId>shiro-redis</artifactId>
<version>3.0.0</version>
</dependency>
```

（2） 在springboot配置文件中添加redis配置

```
redis:
        host: 127.0.0.1
        port: 6379
```

### 4.1.1自定义shiro会话管理器

```java
public class CustomSessionManager extends DefaultWebSessionManager {

    /**
     * 头信息中具有sessionid
     *     请求头：Authorization： sessionid
     *
     * 指定sessionId的获取方式
     */
    @Override
    protected Serializable getSessionId(ServletRequest request, ServletResponse response) {

        //获取请求头Authorization中的数据
        String id = WebUtils.toHttp(request).getHeader("Authorization");
        if (StringUtils.isEmpty(id)) {
            //如果没有携带，生成新的sessionId
            return super.getSessionId(request,response);

        } else {
            //返回sessionId；
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE, "header");
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
            return id;

        }
    }
}
```



### 4.1.2 配置Shiro基于redis的会话管理

1. 配置shiro的RedisManager

```java
@Value("${spring.redis.host}")
private String host;
@Value("${spring.redis.port}")
private int port;

//配置shiro redisManager
public RedisManager redisManager() {
    RedisManager redisManager = new RedisManager();
    redisManager.setHost(host);
    redisManager.setPort(port);
    return redisManager;
}
```

2. Shiro内部有自己的本地缓存机制，为了更加统一方便管理，全部替换redis实现

```java
   			 //配置Shiro的缓存管理器
				//使用redis实现
        public RedisCacheManager cacheManager() {
            RedisCacheManager redisCacheManager = new RedisCacheManager();
            redisCacheManager.setRedisManager(redisManager());
            return redisCacheManager;
        }
```

3. 配置SessionDao，使用shiro-redis实现的基于redis的sessionDao

```java
/**
 * RedisSessionDAO shiro sessionDao层的实现 通过redis
 * 使用的是shiro-redis开源插件
 */
public RedisSessionDAO redisSessionDAO() {
    RedisSessionDAO redisSessionDAO = new RedisSessionDAO();
    redisSessionDAO.setRedisManager(redisManager());
    return redisSessionDAO;
}
```

4. 配置会话管理器，指定sessionDao的依赖关系

```java
/**
 * 3.会话管理器
 */
public DefaultWebSessionManager sessionManager() {
    CustomSessionManager sessionManager = new CustomSessionManager();
    sessionManager.setSessionDAO(redisSessionDAO());
    return sessionManager;
}
```

5. 统一交给SecurityManager管理,不用DefaultWebSecurityManager默认的

```JAVA
//2、创建安全管理器
 //配置安全管理器
@Bean
public SecurityManager securityManager(CustomRealm realm) {
    //使用默认的安全管理器
    DefaultWebSecurityManager securityManager = new
            DefaultWebSecurityManager(realm);
    // 自定义session管理 使用redis
    securityManager.setSessionManager(sessionManager());
    // 自定义缓存实现 使用redis
    securityManager.setCacheManager(cacheManager());
    //将自定义的realm交给安全管理器统一调度管理
    securityManager.setRealm(realm);
    return securityManager;
}
```

# 测试

![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.49ycwj142nm0.jpg)

![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.192werj0q7pc.jpg)

由权限表可知，只要id为1的用户有权限访问user-home接口

##### 登录id=1 的zhangsan

<img src="https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.5qifxsco2a40.jpg" alt="image" style="zoom: 67%;" />



![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.6b1ihkbkcic0.jpg)

把sessionId放入Authorization后登录可以访问成功！

##### 使用id=2 的lisi账户

![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.3k0fdukirwi0.jpg)

![image](https://cdn.staticaly.com/gh/1902756969/picgo_imgs@master/image.24vg1uc14qf4.jpg)

显示未授权