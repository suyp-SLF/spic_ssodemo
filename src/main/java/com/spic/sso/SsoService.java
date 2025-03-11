package com.spic.sso;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import kd.bos.dataentity.utils.ObjectUtils;
import kd.bos.dataentity.utils.StringUtils;
import kd.bos.login.thirdauth.ThirdSSOAuthHandler;
import kd.bos.login.thirdauth.UserAuthResult;
import kd.bos.login.thirdauth.UserProperType;
import kd.bos.monitor.log.KDException;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.filter.state.DefaultStateKeyGenerator;
import org.springframework.security.oauth2.client.filter.state.StateKeyGenerator;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.DefaultUriTemplateHandler;
import org.springframework.web.util.UriTemplateHandler;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import com.alibaba.fastjson.JSONObject;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.*;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SsoService implements ThirdSSOAuthHandler {

	private StateKeyGenerator stateKeyGenerator = new DefaultStateKeyGenerator();
	private AuthorizationCodeResourceDetails resource =getResource();
	private String tokenCookieName = "X-Auth-Token";
	private String savedRequestURICookieName = "X-SavedRequestURI";
	private String IERPCookieSpic = "KERPSESSIONIDspic";
	private String IERPCookie = "KERPSESSIONID";
	Logger logger = LoggerFactory.getLogger(SsoService.class);

	private HttpSession session;
	/**
	 *该方法是用户没有登录的时候插件需要转移到正确的登录地址
	 */
	@Override
	public void callTrdSSOLogin(HttpServletRequest arg0, HttpServletResponse arg1, String arg2) {
		String sessionid = arg0.getSession().getId();
		logger.info("spic_sso:"+sessionid+"--------发送跳转连接进入第三方登录！！");
		long timer0_sso_start = System.currentTimeMillis();
		String url = getUrl(arg0);//跳转链接url
		if(arg0.getServletPath().lastIndexOf("/logout.do") > 0) {
			//注销需处理
			UriTemplateHandler uriTemplateHandler = new DefaultUriBuilderFactory();
			URI uri = uriTemplateHandler.expand(System.getProperty("spic.cus.extUrl"), new Object[] {});
			ClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
			try {
				ClientHttpRequest request = requestFactory.createRequest(uri, HttpMethod.DELETE);
//				request.wait(30000);
				OAuth2AccessToken accessToken = (OAuth2AccessToken) arg0.getServletContext().getAttribute("token");
				request.getHeaders().set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
				Cookie[] cookies = arg0.getCookies();
				String sessionTicket = Arrays.stream(cookies).filter(item -> "sessionTicketName".equalsIgnoreCase(item.getName())).findFirst().get().getValue();
				request.getHeaders().set("Cookie","SESSION=" + sessionTicket);
				boolean timeout = false;
				long timer_sendpost_start_loop = System.currentTimeMillis();
					long timer_sendpost_start = System.currentTimeMillis();
					logger.info("spic_sso:"+sessionid+"--------尝试发送调用普元注销接口");
					request.execute();
				long timer0_sso_end = System.currentTimeMillis();
				logger.info("spic_sso:"+sessionid+"--------调用普元登录注销成功，共耗时：" + (timer0_sso_end - timer0_sso_start) +"ms");
			} catch (Exception e) {
				long timer0_sso_end = System.currentTimeMillis();
				logger.warn("spic_sso:"+sessionid+"--------调用普元登录注销出现错误，共耗时" + (timer0_sso_end - timer0_sso_start) +"ms\r\n" +
						"e:" + getStackTrace(e));
//				throw new KDException(getStackTrace(e));

			}
			HttpSession session = arg0.getSession(false);
			if(session != null) {
				session.invalidate();//清空session
			}
			cleanCookie(tokenCookieName, arg1);
			cleanCookie(savedRequestURICookieName, arg1);
			arg1.setStatus(HttpStatus.FOUND.value());
			if("/auth/logServletPath".equalsIgnoreCase(arg0.getServletPath())){
				cleanCookie(IERPCookieSpic, arg1);
				cleanCookie(IERPCookie, arg1);
			}
			url = getUrl(arg0, new StringBuffer(System.getProperty("domain.contextUrl")));
		}
		
		//TODO 判断逻辑 是否需要跳转第三方登录界面
		if(StringUtils.isNotEmpty(arg0.getParameter("code")) && arg0.getServletPath().lastIndexOf("/logout.do") < 0) {
			  return;
		}
		long timer_redirect_start = System.currentTimeMillis();
		try {
/*			sessionid = arg0.getSession().getId();
			logger.info("spic_sso:"+sessionid+"--------开始调用普元token接口");
			ClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
			ClientHttpRequest request = requestFactory.createRequest(URI.create(url), HttpMethod.POST);
			OAuth2AccessToken accessToken = (OAuth2AccessToken) arg0.getServletContext().getAttribute("token");
			long redirect_post_start = System.currentTimeMillis();
			InputStream response = request.execute().getBody();
			long redirect_post_end = System.currentTimeMillis();
			logger.info("spic_sso:"+sessionid+"--------调用普元token成功，共耗时：" + (redirect_post_end - redirect_post_start) +"ms");
			byte[] bytes = new byte[0];
			bytes = new byte[response.available()];
			response.read(bytes);
			String str = new String(bytes);
			long dispose_tokenjson_start = System.currentTimeMillis();
			logger.info("spic_sso:" + sessionid + "--------开始解析普元token返回值，解析方式json，报文：\r\n" + str);
			if(StringUtils.isNotBlank(str)){
				JSONObject json = JSONObject.parseObject(str);

				String access_token =json.getString("access_token");
				String refresh_token = json.getString("refresh_token");

				Cookie access_token_cookie = new Cookie("X-Auth-Token", access_token);
				arg1.addCookie(access_token_cookie);
				Cookie refresh_token_cookie = new Cookie("X-Refresh-Token", refresh_token);
				arg1.addCookie(refresh_token_cookie);
				long dispose_tokenjson_end = System.currentTimeMillis();
				logger.info("spic_sso:" + sessionid + "--------解析普元token返回值完成，共耗时："+(dispose_tokenjson_end - dispose_tokenjson_start)+"\r\n" +
						"access_token:" + access_token + "\r\n" +
						"refresh_token:" + refresh_token + "\r\n");
			}*/
			arg1.sendRedirect(url);
			long timer_redirect_end = System.currentTimeMillis();
			logger.info("spic_sso:"+sessionid+"--------调用普元token成功，完成转发，共耗时：" + (timer_redirect_end - timer_redirect_start) +"ms" +
					"转发地址url：" + url);
		} catch (IOException e) {
			long timer_redirect_end = System.currentTimeMillis();
			logger.info("spic_sso:"+sessionid+"--------调用普元token，完成转发失败，共耗时：" + (timer_redirect_end - timer_redirect_start) +"ms" +
					"e" + getStackTrace(e));
			throw new KDException(getStackTrace(e));
		}
	}
	/**
	 * 指定重定向url
	 * @param request
	 * @param url
	 * @return
	 */
	private String getUrl(HttpServletRequest request,StringBuffer url) {
			logger.info("开始重定向到第三方认证平台");
			if (resource == null) {
				resource = getResource();
			}
			String stateKey = stateKeyGenerator.generateKey(resource);
			StringBuilder sb = new StringBuilder();
			sb.append(resource.getUserAuthorizationUri());
			sb.append("?client_id=");
			sb.append(resource.getClientId());
			sb.append("&redirect_uri=");
			String contextUrl = System.getProperty("domain.contextUrl");
			if (url == null) {
				url = new StringBuffer(contextUrl);
			}
			sb.append(url);
			sb.append("&response_type=code&scope=");
			sb.append(resource.getScope().get(0));
			sb.append("&state=");
			sb.append(stateKey);
			logger.info("第三方认证平台重定向成功! {}", sb);
			return sb.toString();
	}
	
	/**
	 * 资源文件
	 * @return
	 */
	private static AuthorizationCodeResourceDetails getResource() {
		AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
		resource.setClientId(System.getProperty("spic.cus.clientId"));//#该值需要在统一认证中心注册系统后生成提供
		resource.setClientSecret(System.getProperty("spic.cus.clientSecret"));//#该值需要在统一认证中心注册系统后生成提供
		resource.setAccessTokenUri(System.getProperty("spic.cus.loginUrl")+"/oauth/token");
		resource.setAuthenticationScheme(AuthenticationScheme.header);
		resource.setClientAuthenticationScheme(AuthenticationScheme.header);
		List<String> list = new ArrayList<String>();
		list.add("default");
		resource.setScope(list);
		resource.setTokenName("access_token");
		resource.setUseCurrentUri(true);
		resource.setUserAuthorizationUri(System.getProperty("spic.cus.loginUrl")+"/oauth/authorize");
		return resource;
	}
	
	/**
	 * 该方法实现第三发插件认证及认证结果的返回
	 */
	@Override
	public UserAuthResult getTrdSSOAuth(HttpServletRequest request, HttpServletResponse response) {

		String sessionid = request.getSession().getId();
		long sso_login_start = System.currentTimeMillis();
		logger.info("spic_sso:"+sessionid+"--------开始调用普元登录接口");
		UserAuthResult result=new UserAuthResult();
		result.setSucess(false);
		//这里编写自己的登录逻辑，判断是否登陆成功，并填写正确的返回类型和返回值
		if(StringUtils.isEmpty(request.getParameter("code"))) {
			return result;
		}
		AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();
		OAuth2AccessToken accessToken = null;
		AccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest();
		accessTokenRequest.add("code", request.getParameter("code"));
		accessTokenRequest.add("state", request.getParameter("state"));
		StringBuffer urL = new StringBuffer(System.getProperty("domain.contextUrl"));
		accessTokenRequest.setPreservedState(urL.toString());
		accessTokenRequest.setStateKey(request.getParameter("state"));
		long acctoken_run_start = System.currentTimeMillis();
		accessToken = provider.obtainAccessToken(resource, accessTokenRequest);
		long acctoken_run_end = System.currentTimeMillis();
		logger.info("spic_sso:"+sessionid+"--------调用普元acctoken完成，共耗时：" + (acctoken_run_end - acctoken_run_start) + "ms");
		request.getServletContext().setAttribute("token", accessToken);//将token存入到上下文中
		JwtAccessTokenConverter jwtTokenEnhancer = new JwtAccessTokenConverter();
		jwtTokenEnhancer.setVerifier(new MacSigner("non-prod-signature"));// jwt key-value:
		JwtTokenStore jwtTokenStore = new JwtTokenStore(jwtTokenEnhancer);
		OAuth2Authentication oAuth2Authentication = jwtTokenStore.readAuthentication(accessToken);
		Authentication authentication = oAuth2Authentication.getUserAuthentication();
		Map<String, String> authenticationDetails = (LinkedHashMap<String, String>) authentication.getDetails();

		Algorithm algorithm = Algorithm.HMAC256("non-prod-signature");
		JWTVerifier jwtVerifier = JWT.require(algorithm).build();
		DecodedJWT verify = jwtVerifier.verify(accessToken.getValue());
		String sessionTicket = verify.getClaim("SESSION").asString();

		Cookie sessionTicketCookie = new Cookie("sessionTicketName",sessionTicket);
		response.addCookie(sessionTicketCookie);

		if(!ObjectUtils.isEmpty(authentication.getPrincipal())){
			result.setUserType(UserProperType.UserName);
			result.setUser(authentication.getPrincipal());
			result.setSucess(true);
		}
		long sso_login_end = System.currentTimeMillis();
		logger.info("spic_sso:"+sessionid+"--------开始调用普元登录接口完成，共耗时：" + (sso_login_end - sso_login_start)+ "ms\r\n" +
				"Details："+ authentication.getDetails() +"\r\n" +
				"Name："+ authentication.getName() +"\r\n" +
				"Principal："+ authentication.getPrincipal() +"\r\n" );
		return result;
	}
	
	/**
	 * @param cookieName
	 * @param response
	 */
	private void cleanCookie(String cookieName, HttpServletResponse response) {
		Cookie cookie = new Cookie(cookieName, (String)null);
		cookie.setMaxAge(0);
		cookie.setPath("/");
		response.addCookie(cookie);
	}
	
	
	/**
	 * 封装跳转路径 url
	 * @param request 
	 * @return
	 */
	private String getUrl(HttpServletRequest request) {
		return getUrl(request, null);
	}


	public static String getStackTrace(Throwable throwable){
		if (null != throwable) {
			StringWriter stringWriter=new StringWriter();
			PrintWriter printWriter=new PrintWriter(stringWriter);
			try {
				throwable.printStackTrace(printWriter);
				return throwable.getMessage() + stringWriter.toString();
			}finally {
				printWriter.close();
			}
		} else {
			return "";
		}
	}
}
