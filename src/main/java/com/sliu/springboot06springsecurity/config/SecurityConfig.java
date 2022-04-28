package com.sliu.springboot06springsecurity.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//AOP原理实现拦截器
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//   链式编程
//    授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //设置首页所有人可见，level页面对应权限可见
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        //没有权限默认跳转登陆页面
//        自定义登录页
        http.formLogin().loginPage("/toLogin").usernameParameter("user").passwordParameter("pwd").loginProcessingUrl("/login");

        //开启注销
        http.logout().logoutSuccessUrl("/");

//        防止网站攻击：get&post,登陆失败可能存在的原因
        http.csrf().disable();

//        开启记住我，Cookie默认保存两周，同时为了整合自定义的首页，接收前端参数，用于判断remenber me功能在哪里触发
        http.rememberMe().rememberMeParameter("remember");
    }

//    认证
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

//        仿照数据库数据，真实应用场景下应从数据库读入
        auth.inMemoryAuthentication()
                .withUser("sliu").password("{noop}123456").roles("vip1", "vip2")
                .and()
                .withUser("root").password("{noop}123456").roles("vip1", "vip2", "vip3")
                .and()
                .withUser("guest").password("{noop}123456").roles("vip1");
    }

}
