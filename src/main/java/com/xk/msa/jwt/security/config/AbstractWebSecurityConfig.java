package com.xk.msa.jwt.security.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.xk.msa.jwt.security.RestAuthenticationEntryPoint;
import com.xk.msa.jwt.security.auth.jwt.JwtAuthenticationProvider;
import com.xk.msa.jwt.security.auth.jwt.JwtTokenAuthenticationProcessingFilter;
import com.xk.msa.jwt.security.auth.jwt.SkipPathRequestMatcher;
import com.xk.msa.jwt.security.auth.jwt.extractor.TokenExtractor;

/**
 * 
 * @author yanhaixun
 * @date 2017年3月23日 上午9:41:14
 *
 */
public abstract class AbstractWebSecurityConfig extends WebSecurityConfigurerAdapter {
    public static final String JWT_TOKEN_HEADER_PARAM = "XK-Autho1.0.0";
    @Value("${com.xk.msa.security.jwt.tokenFormBasedLoginEntryPoint}")
    public  String FORM_BASED_LOGIN_ENTRY_POINT;// = "/api/xkauth/login";
    public static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/api/**";
    @Value("${com.xk.msa.security.jwt.tokenRefreshAuthEntryPoint}")
    public String TOKEN_REFRESH_ENTRY_POINT ;//= "/api/xkauth/token";
    
    @Autowired protected RestAuthenticationEntryPoint authenticationEntryPoint;
   
    @Autowired protected AuthenticationFailureHandler failureHandler;
//    @Autowired private AjaxAuthenticationProvider ajaxAuthenticationProvider;
    @Autowired protected JwtAuthenticationProvider jwtAuthenticationProvider;
    
    @Autowired protected TokenExtractor tokenExtractor;
    
    @Autowired protected AuthenticationManager authenticationManager;
    
        
//    protected AjaxLoginProcessingFilter buildAjaxLoginProcessingFilter() throws Exception {
//        AjaxLoginProcessingFilter filter = new AjaxLoginProcessingFilter(FORM_BASED_LOGIN_ENTRY_POINT, successHandler, failureHandler, objectMapper);
//        filter.setAuthenticationManager(this.authenticationManager);
//        return filter;
//    }
    
    protected JwtTokenAuthenticationProcessingFilter buildJwtTokenAuthenticationProcessingFilter() throws Exception {
        List<String> pathsToSkip = Arrays.asList(TOKEN_REFRESH_ENTRY_POINT, FORM_BASED_LOGIN_ENTRY_POINT);
        SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(pathsToSkip, TOKEN_BASED_AUTH_ENTRY_POINT);
        JwtTokenAuthenticationProcessingFilter filter 
            = new JwtTokenAuthenticationProcessingFilter(failureHandler, tokenExtractor, matcher);
        filter.setAuthenticationManager(this.authenticationManager);
        return filter;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
//        auth.authenticationProvider(ajaxAuthenticationProvider);
        auth.authenticationProvider(jwtAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//        .requestMatchers().antMatchers(HttpMethod.OPTIONS, "/api/oauth/token", "/rest/**", "/api/**", "/**")
//        .and()
        .csrf().disable() // We don't need CSRF for JWT based authentication
        .exceptionHandling()
        .authenticationEntryPoint(this.authenticationEntryPoint)        
        .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
            .authorizeRequests()
//                .antMatchers(FORM_BASED_LOGIN_ENTRY_POINT).permitAll() // Login end-point
                .antMatchers(TOKEN_REFRESH_ENTRY_POINT).permitAll() // Token refresh end-point
                .antMatchers("/console").permitAll() // H2 Console Dash-board - only for testing
        .and()
            .formLogin()
                .loginPage(FORM_BASED_LOGIN_ENTRY_POINT)
                .permitAll()
        .and()
            .logout()
                .permitAll()                
        .and()
            .authorizeRequests()
                .antMatchers(TOKEN_BASED_AUTH_ENTRY_POINT).authenticated(); // Protected API End-points
        
        setupAuthorization(http);
        
        http
//        .addFilterBefore(buildAjaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
        .addFilterBefore(buildJwtTokenAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
       

//		http.addFilterBefore(jsonWebTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }
    protected abstract void setupAuthorization(HttpSecurity http) throws Exception;
}
