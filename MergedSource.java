// File: scg\build.gradle
dependencies {
    implementation 'org.springframework.cloud:spring-cloud-starter-gateway'
    implementation 'org.springframework.cloud:spring-cloud-starter-netflix-eureka-client'
    implementation 'org.springframework.cloud:spring-cloud-starter-loadbalancer'

    implementation 'io.jsonwebtoken:jjwt-api:0.12.5'
    implementation 'io.jsonwebtoken:jjwt-impl:0.12.5'
    implementation 'io.jsonwebtoken:jjwt-jackson:0.12.5'

    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'
}

bootJar {
    archiveFileName = "scg.jar"
}



// File: scg\src\main\java\com\sc\scg\ScgApplication.java
package com.sc.scg;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class ScgApplication {
    public static void main(String[] args) {
        SpringApplication.run(ScgApplication.class, args);
    }
}


// File: scg\src\main\java\com\sc\scg\filter\auth\JwtUtil.java
package com.sc.scg.filter.auth;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@SuppressWarnings("unused")
public class JwtUtil {
    private final SecretKey secretKey;

    public JwtUtil(@Value("${spring.jwt.secret}")String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8),
                Jwts.SIG.HS512.key().build().getAlgorithm());
    }

    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String createJwt(String username, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }
}

// File: scg\src\main\java\com\sc\scg\filter\logger\PostLogger.java
package com.sc.scg.filter.logger;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import lombok.Getter;
import lombok.Setter;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class PostLogger extends AbstractGatewayFilterFactory<PostLogger.Config> {

    public PostLogger() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> chain.filter(exchange).then(Mono.fromRunnable(() -> {
            if (config.isLogging()) {
                logResponse(exchange, config);
            }
        }));
    }

    private void logResponse(ServerWebExchange exchange, Config config) {
        ServerHttpResponse response = exchange.getResponse();

        String logMessage = "Response logged: " +
                config.getBaseMessage() +
                "\n" +
                "Status code: " + response.getStatusCode() +
                "\n" +
                "Headers: " + response.getHeaders() +
                "\n";

        log.info(logMessage);
    }

    @Getter
    @Setter
    public static class Config {
        private String baseMessage = "PostLogger Filter";
        private boolean logging = true;
    }
}


// File: scg\src\main\java\com\sc\scg\filter\logger\PreLogger.java
package com.sc.scg.filter.logger;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;
import org.springframework.web.server.ServerWebExchange;

@Slf4j
@Component
public class PreLogger extends AbstractGatewayFilterFactory<PreLogger.Config> {
    public PreLogger() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        //grab configuration from Config object
        return (exchange, chain) -> {
            if (config.isLogging()) {
                logRequest(exchange, config);
            }

            ServerHttpRequest.Builder builder = exchange.getRequest().mutate();
            return chain.filter(exchange.mutate().request(builder.build()).build());
        };
    }
    private void logRequest(ServerWebExchange exchange, Config config) {
        ServerHttpRequest request = exchange.getRequest();

        String logMessage = "Request logged: " +
                config.getBaseMessage() +
                "\n" +
                "Method: " + request.getMethod() +
                "\n" +
                "Path: " + request.getURI().getPath() +
                "\n" +
                "Headers: " + request.getHeaders() +
                "\n";

        log.info(logMessage);
    }

    @Getter
    @Setter
    public static class Config {
        private String baseMessage;
        private boolean logging;

    }
}

// File: D:\home\ondal\workspace\sc\settings.gradle
rootProject.name = 'sc'
include 'config'
include 'eureka'
include 'scg'



