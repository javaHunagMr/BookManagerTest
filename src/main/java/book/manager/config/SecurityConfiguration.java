package book.manager.config;

import book.manager.entity.AuthUser;
import book.manager.mapper.UserMapper;
import book.manager.service.impl.UserAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.sql.DataSource;
import java.io.IOException;

/**
 * @author 33904
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter  {

    @Resource
    UserAuthService service;
    @Resource
    PersistentTokenRepository repository;
    @Resource
    UserMapper mapper;

    @Bean
    public PersistentTokenRepository jdbcRepository(@Autowired DataSource dataSource){
        JdbcTokenRepositoryImpl repository = new JdbcTokenRepositoryImpl();  //使用基于JDBC的实现
        repository.setDataSource(dataSource);   //配置数据源
        return repository;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()   //首先需要配置哪些请求会被拦截，哪些请求必须具有什么角色才能访问
                .antMatchers("/static/**","/page/auth/**","/api/auth/**").permitAll()
                .antMatchers("/page/user/**","/api/user/**").hasRole("user")
                .antMatchers("/page/admin/**", "/api/admin/**").hasRole("admin")
                .anyRequest().hasAnyRole("user","admin")
                .and()
                .formLogin()       //配置Form表单登陆
                .loginPage("/page/auth/login")       //登陆页面地址（GET）
                .loginProcessingUrl("/api/auth/login")    //form表单提交地址（POST）
                .successHandler(this::onAuthenticationSuccess)
                //.defaultSuccessUrl("/index",true)    //登陆成功后跳转的页面，也可以通过Handler实现高度自定义
                //.permitAll()    //登陆页面也需要允许所有人访问
                .and()
                .logout()
                .logoutUrl("/api/auth/logout")    //退出登陆的请求地址
                .logoutSuccessUrl("/login")    //退出后重定向的地址
                .and()
                .csrf().disable()
                .rememberMe()   //开启记住我功能
                .rememberMeParameter("remember")  //登陆请求表单中需要携带的参数，如果携带，那么本次登陆会被记住
                .tokenRepository(new InMemoryTokenRepositoryImpl())
                .and()
                .rememberMe()
                .rememberMeParameter("remember")
                .tokenRepository(repository)
                .tokenValiditySeconds(60 * 60 * 24 * 7);  //Token的有效时间（秒）默认为14天





    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(service)
                .passwordEncoder(new BCryptPasswordEncoder()); //密码加密器
    }

    private void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        HttpSession session = httpServletRequest.getSession();
        AuthUser user = mapper.getPasswordByUsername(authentication.getName());
        session.setAttribute("user", user);
        //httpServletResponse.sendRedirect("/bookmanager/index");
        if(user.getRole().equals("admin")){
            httpServletResponse.sendRedirect("/bookmanager/page/admin/index");
        }else {
            httpServletResponse.sendRedirect("/bookmanager/page/user/index");
        }
    }
}
