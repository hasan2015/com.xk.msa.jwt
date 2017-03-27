package com.xk.msa.jwt.security.auth.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

//import com.xk.msa.ca.security.config.WebSecurityConfig;
import com.xk.msa.jwt.security.auth.JwtAuthenticationToken;
import com.xk.msa.jwt.security.auth.jwt.extractor.TokenExtractor;
import com.xk.msa.jwt.security.model.token.RawAccessJwtToken;
 
/**
 * Performs validation of provided JWT Token.
 * @author yanhaixun
 * @date 2017年3月18日 下午12:21:22
 *
 */
public class JwtTokenAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {
	private final AuthenticationFailureHandler failureHandler;
	private final TokenExtractor tokenExtractor;
	@Value("${com.xk.msa.security.jwt.tokenHeader}")
    private String JWT_TOKEN_HEADER_PARAM;
	@Autowired
	public JwtTokenAuthenticationProcessingFilter(AuthenticationFailureHandler failureHandler,
			TokenExtractor tokenExtractor, RequestMatcher matcher) {
		super(matcher);
		this.failureHandler = failureHandler;
		this.tokenExtractor = tokenExtractor;
	}

	/**
	 * 检查访问令牌在X-Authorization头。如果发现访问令牌的头,委托认证JwtAuthenticationProvider否则抛出身份验证异常
	 */
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		String tokenPayload = request.getHeader(JWT_TOKEN_HEADER_PARAM);
		RawAccessJwtToken token = new RawAccessJwtToken(tokenExtractor.extract(tokenPayload));
		//调用成功或失败策略基于由JwtAuthenticationProvider执行身份验证过程的结果
		return getAuthenticationManager().authenticate(new JwtAuthenticationToken(token));
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authResult);
		SecurityContextHolder.setContext(context);
		chain.doFilter(request, response);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		SecurityContextHolder.clearContext();
		failureHandler.onAuthenticationFailure(request, response, failed);
	}
}
