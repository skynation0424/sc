package com.sc.scg.filter.auth;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Component
@SuppressWarnings("unused")
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    @Autowired
    private JwtUtil jwtUtil;

    public AuthorizationHeaderFilter() {
        super(Config.class);
    }

    public static class Config {
        // application.yml 파일에서 지정한 filer의 Argument값을 받는 부분
    }

    @Override
    public GatewayFilter apply(Config config) {
        log.info("************* Check Authorization");
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if (request.getURI().getPath().startsWith("/api/auth")) {
                return chain.filter(
                        exchange.mutate().request(
                                exchange.getRequest().mutate().build()
                        ).build());
            }

            List<String> authHeaders = request.getHeaders().get("Authorization");

            if (authHeaders == null || authHeaders.isEmpty()) {
                return onError(exchange, HttpStatus.BAD_REQUEST, "100");
            }

            String token = authHeaders.get(0).substring(7);
            String username;

            try {
                username = jwtUtil.getUsername(token);
            } catch (ExpiredJwtException ex) {
                return onError(exchange, HttpStatus.UNAUTHORIZED, "200");
            } catch (Exception ex) {
                return onError(exchange, HttpStatus.INTERNAL_SERVER_ERROR, "500");
            }

            exchange.getRequest().mutate().header("X-Authorization-Id", username).build();

            return chain.filter(
                    exchange.mutate().request(
                            exchange.getRequest().mutate().build()
                    ).build());

        };
    }

    private Mono<Void> onError(@NonNull ServerWebExchange exchange, @NonNull HttpStatus status, @NonNull String errorCode) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String errorResponse = "{\"errorCode\": \"" + errorCode + "\"}";
        byte[] bytes = errorResponse.getBytes();

        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
    }

    @Bean
    public ErrorWebExceptionHandler tokenValidation() {
        return new JwtTokenExceptionHandler();
    }

    public static class JwtTokenExceptionHandler implements ErrorWebExceptionHandler {
        @Override
        @NonNull
        public Mono<Void> handle(@NonNull ServerWebExchange exchange, @NonNull Throwable ex) {
            HttpStatus status;
            String errorCode;

            if (ex instanceof NullPointerException) {
                status = HttpStatus.BAD_REQUEST;
                errorCode = "100";
            } else if (ex instanceof ExpiredJwtException) {
                status = HttpStatus.UNAUTHORIZED;
                errorCode = "200";
            } else {
                status = HttpStatus.INTERNAL_SERVER_ERROR;
                errorCode = "500";
            }

            exchange.getResponse().setStatusCode(status);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

            String errorResponse = "{\"errorCode\": \"" + errorCode + "\"}";
            byte[] bytes = errorResponse.getBytes();

            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
        }
    }
}