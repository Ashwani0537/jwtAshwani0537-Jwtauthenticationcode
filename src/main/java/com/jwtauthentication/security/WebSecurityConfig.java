package com.jwtauthentication.security;

//package com.jwtSecurity.javaAuthontication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.jwtauthentication.jwtrequestfilter.JwtRequestFilter;

@SuppressWarnings("deprecation")
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfiguration {

	@Autowired
	private UserDetailsService myUserDetailsService;
	
	
	
	@Autowired
	 private JwtRequestFilter jwtRequestfilter ;
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(myUserDetailsService);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return  authenticationManagerBean();
	}

	protected void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.csrf()
							.disable()
							.authorizeRequests()
							.requestMatchers("/token")
							.permitAll()
							.anyRequest()
							.authenticated()
							.and()
							.exceptionHandling()
							.and()
							.sessionManagement()
							.sessionCreationPolicy(SessionCreationPolicy.STATELESS);

httpSecurity.addFilterBefore(jwtRequestfilter , UsernamePasswordAuthenticationFilter.class);
}
}


