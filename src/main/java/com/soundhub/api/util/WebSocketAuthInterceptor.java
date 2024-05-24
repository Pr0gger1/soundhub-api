package com.soundhub.api.util;

import com.soundhub.api.Constants;
import com.soundhub.api.security.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.nio.file.AccessDeniedException;


@Slf4j
public class WebSocketAuthInterceptor implements ChannelInterceptor {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        log.debug("preSend[1]: message: {}", message);
        final StompHeaderAccessor headerAccessor = MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);
        StompCommand cmd = headerAccessor.getCommand();

        if (StompCommand.CONNECT == cmd || StompCommand.SEND == cmd) {
            String authorizationHeader = headerAccessor.getFirstNativeHeader(Constants.AUTHORIZATION_HEADER_NAME);
            if (authorizationHeader != null && authorizationHeader.startsWith(Constants.BEARER_PREFIX)) {
                String token = authorizationHeader.substring(7);

                try {
                    String username = jwtService.extractUsername(token);
                    log.debug("preSend[2]: username: {}", username);
                    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                        if (jwtService.isTokenValid(token, userDetails)) {
                            Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                            headerAccessor.setUser(authentication);
                        }
                    }
                } catch (UsernameNotFoundException e) {
                    log.error("preSend[1]: error: {}", e.getMessage());
//                    throw new AccessDeniedException("Invalid token or user not found");
                    throw new RuntimeException(e);
                }
            }
        }
        return message;
    }
}
