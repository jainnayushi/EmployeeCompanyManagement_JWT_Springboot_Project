package com.assignment.EmployeeCompany.config;

import com.assignment.EmployeeCompany.entity.ResponseMessage;
import com.assignment.EmployeeCompany.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    UserService userService;

    @Autowired
    JwtGeneratorValidator jwtgenVal;

    private final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");

        String token = null;
        String userName = null;
        String requestURI = request.getRequestURI();
        if ("/registration".equals(requestURI) || "/genToken".equals(requestURI)) {
            // Skip JWT verification for the specific path
            filterChain.doFilter(request, response);
        }
        else {
            // Perform JWT verification for other paths
            // ... your JWT verification logic here ...

            try {


                if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                    token = authorizationHeader.substring(7);
                    userName = jwtgenVal.extractUsername(token);
                }else {
                    ResponseEntity<ResponseMessage> entity = ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(new ResponseMessage(Boolean.FALSE, "Token is mandatory"));
                    sendResponse(response, entity);
                    logger.error("Token is mandatory");
                    return;
                }

                if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = userService.loadUserByUsername(userName);

                    if (jwtgenVal.validateToken(token, userDetails)) {
                        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                        logger.trace("User '{}' successfully authenticated.", userDetails.getUsername());
                    } else {
                        logger.warn("Invalid JWT token for user '{}'", userDetails.getUsername());
                        ResponseEntity<ResponseMessage> entity =ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ResponseMessage(Boolean.FALSE, "Invalid JWT token for user"+userDetails.getUsername()));
                        sendResponse(response, entity);
                        return;
                    }
                }
            } catch (ExpiredJwtException e) {
                logger.error("Given JWT token is expired");
                ResponseEntity<ResponseMessage> entity = ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                        .body(new ResponseMessage(Boolean.FALSE, "Given JWT token is expired."));
                sendResponse(response, entity);
                return;
            } catch (Exception e) {
                logger.error("An error occurred during JWT authentication: {}", e.getMessage());
                ResponseEntity<ResponseMessage> entity = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ResponseMessage(Boolean.TRUE, "An error occurred during JWT authentication"));
                sendResponse(response, entity);
                return;
            }

            filterChain.doFilter(request, response);
        }
    }
    public void sendResponse(HttpServletResponse response, ResponseEntity<ResponseMessage> entity) throws IOException {
        response.setStatus(entity.getStatusCodeValue());
        response.setContentType("application/json");
//        response.getWriter().write(entity.getBody().toString());
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.writeValue(response.getWriter(), entity.getBody());
    }

}