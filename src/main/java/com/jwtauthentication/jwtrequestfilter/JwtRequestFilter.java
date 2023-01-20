package com.jwtauthentication.jwtrequestfilter;

import java.io.IOException;

//package com.jwtSecurity.javaAuthontication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.jwtauthentication.security.MyUserDetailsService;
import com.jwtauthentication.util.Jwtutil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

  @Autowired
  private MyUserDetailsService userDetailsService;

  @Autowired
  private Jwtutil jwtUtil;
  
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
          throws ServletException, IOException {

      final String authorizationHeader = request.getHeader("Authorization");

      String username = null;
      String jwt = null;
      
      if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
          jwt = authorizationHeader.substring(7);
          username = jwtUtil.extractUsername(jwt);
      }
      
      if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

          UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

          if (jwtUtil.validateToken(jwt, userDetails)) {

              UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                      userDetails, null, userDetails.getAuthorities());
              usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
              SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
          }
      }
      chain.doFilter(request, response);
  }
}


