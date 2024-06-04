// File: scg/build.gradle
dependencies {
    implementation 'org.springframework.cloud:spring-cloud-starter-gateway'
    implementation 'org.springframework.cloud:spring-cloud-starter-netflix-eureka-client'

    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'com.auth0:java-jwt:4.4.0'			//JWT unitlity

    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'

}


// File: scg/build/resources/main/application.yml
server:
  port: ${SERVER_PORT:19080}
spring:
  application:
    name: scg
eureka:
  client:
    service-url:
      defaultZone: ${EUREKA_SERVERS:http://eureka1.127.0.0.1.nip.io:8761/eureka/,http://eureka2.127.0.0.1.nip.io:8762/eureka/}
    registryFetchIntervalSeconds: 60
    instanceInfoReplicationIntervalSeconds: 60

logging:
  level:
    root: INFO
    org.springframework.cloud.gateway: ERROR

#========= 라우팅
spring.cloud.gateway:
  # Timeout
  httpclient:
    connect-timeout: 1000
    response-timeout: 2000

  # Routing
  routes:
    - id: auth
      uri: lb://member-service
      predicates:
        - Path=/api/auth/**

    - id: member
      uri: lb://member-service
      predicates:
        - Path=/api/members/**

    - id: subrecommend
      uri: lb://subrecommend-service
      predicates:
        - Path=/api/subrecommend/**

    - id: mygrp
      uri: lb://mygrp-service
      predicates:
        - Path=/api/my-groups/**

    - id: mysub
      uri: lb://mysub-service
      predicates:
        - Path=/api/my-subs/**

    - id: transfer
      uri: lb://transfer-service
      predicates:
        - Path=/api/transfer/**
      filters:
        - name: Retry
          args:
            retries: 5              # 재시도 횟수
            statuses: BAD_GATEWAY, INTERNAL_SERVER_ERROR, SERVICE_UNAVAILABLE #재시도 할 응답상태
            methods: GET, POST  # 재시도 메소드
            backoff:
              firstBackoff: 500ms   #첫번째 재시도는 실패 후 0.5초 후 수행
              maxBackoff: 2000ms    #재시도 간격
              factor: 10            #firstBackoff * (factor^retries)가 재시도 간격임. maxBackoff보다 클 수는 없음.
              #exceptions:             # Connect가 안되는 경우에만 retry(POST일때는 불필요한 재시도 방지를 위해 설정하는게 좋음)
              #- java.net.ConnectException
      metadata: #현재 요청에 대해서만 Timeout 정의 시
        connect-timeout: 1000
        response-timeout: 1000

# 그 외 application.yml에 설정 예제는 아래 페이지 참조
# https://happycloud-lee.tistory.com/218
#========================

---   #동일한 키인 spring.cloud.gateway를 사용하기 할때 사용
spring.cloud.gateway:
#========= Logging ===========
# Request Logging
  default-filters:
    - name: PreLogger
      args:
        logging: true
        baseMessage: "######### Logging for Request ############"
# Response Logging
    - name: PostLogger
      args:
        logging: true
        baseMessage: "######### Logging for Response ############"
#=============================
---
#======= 인증 유효성 검사 ========
spring.cloud.gateway:
  default-filters:
    - name: JwtAuthenticationFilter
jwt:
  secret: 8O2HQ13etL2BWZvYOiWsJ5uWFoLi6NBUG8divYVoCgtHVvlk3dqRksMl16toztDUeBTSIuOOPvHIrYq11G2BwQ==
allowedOrigins: http://localhost:3000
#=============================

---
#======= 중복 헤더 제거 ==========
spring.cloud.gateway:
  default-filters:
    # 중요) 응답에 지정된 헤더가 중복되면 하나만 남김. 다른 필터와의 우선순위로 동작 안할 수 있으므로 가장 마지막에 지정
    - DedupeResponseHeader=Access-Control-Allow-Credentials Access-Control-Allow-Origin
#=============================

// File: scg/src/main/resources/application.yml
server:
  port: ${SERVER_PORT:19080}
spring:
  application:
    name: scg
eureka:
  client:
    service-url:
      defaultZone: ${EUREKA_SERVERS:http://eureka1.127.0.0.1.nip.io:8761/eureka/,http://eureka2.127.0.0.1.nip.io:8762/eureka/}
    registryFetchIntervalSeconds: 60
    instanceInfoReplicationIntervalSeconds: 60

logging:
  level:
    root: INFO
    org.springframework.cloud.gateway: ERROR

#========= 라우팅
spring.cloud.gateway:
  # Timeout
  httpclient:
    connect-timeout: 1000
    response-timeout: 2000

  # Routing
  routes:
    - id: auth
      uri: lb://member-service
      predicates:
        - Path=/api/auth/**

    - id: member
      uri: lb://member-service
      predicates:
        - Path=/api/members/**

    - id: subrecommend
      uri: lb://subrecommend-service
      predicates:
        - Path=/api/subrecommend/**

    - id: mygrp
      uri: lb://mygrp-service
      predicates:
        - Path=/api/my-groups/**

    - id: mysub
      uri: lb://mysub-service
      predicates:
        - Path=/api/my-subs/**

    - id: transfer
      uri: lb://transfer-service
      predicates:
        - Path=/api/transfer/**
      filters:
        - name: Retry
          args:
            retries: 5              # 재시도 횟수
            statuses: BAD_GATEWAY, INTERNAL_SERVER_ERROR, SERVICE_UNAVAILABLE #재시도 할 응답상태
            methods: GET, POST  # 재시도 메소드
            backoff:
              firstBackoff: 500ms   #첫번째 재시도는 실패 후 0.5초 후 수행
              maxBackoff: 2000ms    #재시도 간격
              factor: 10            #firstBackoff * (factor^retries)가 재시도 간격임. maxBackoff보다 클 수는 없음.
              #exceptions:             # Connect가 안되는 경우에만 retry(POST일때는 불필요한 재시도 방지를 위해 설정하는게 좋음)
              #- java.net.ConnectException
      metadata: #현재 요청에 대해서만 Timeout 정의 시
        connect-timeout: 1000
        response-timeout: 1000

# 그 외 application.yml에 설정 예제는 아래 페이지 참조
# https://happycloud-lee.tistory.com/218
#========================

---   #동일한 키인 spring.cloud.gateway를 사용하기 할때 사용
spring.cloud.gateway:
#========= Logging ===========
# Request Logging
  default-filters:
    - name: PreLogger
      args:
        logging: true
        baseMessage: "######### Logging for Request ############"
# Response Logging
    - name: PostLogger
      args:
        logging: true
        baseMessage: "######### Logging for Response ############"
#=============================
---
#======= 인증 유효성 검사 ========
spring.cloud.gateway:
  default-filters:
    - name: JwtAuthenticationFilter
jwt:
  secret: 8O2HQ13etL2BWZvYOiWsJ5uWFoLi6NBUG8divYVoCgtHVvlk3dqRksMl16toztDUeBTSIuOOPvHIrYq11G2BwQ==
allowedOrigins: http://localhost:3000
#=============================

---
#======= 중복 헤더 제거 ==========
spring.cloud.gateway:
  default-filters:
    # 중요) 응답에 지정된 헤더가 중복되면 하나만 남김. 다른 필터와의 우선순위로 동작 안할 수 있으므로 가장 마지막에 지정
    - DedupeResponseHeader=Access-Control-Allow-Credentials Access-Control-Allow-Origin
#=============================

// File: scg/src/main/java/com/sc/scg/ScgApplication.java
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


// File: scg/src/main/java/com/sc/scg/jwt/JwtTokenProvider.java
// CommonJwtTokenProvider.java
package com.sc.scg.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtTokenProvider {
    private final Algorithm algorithm;

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        this.algorithm = Algorithm.HMAC512(secretKey);
    }

    public Authentication getAuthentication(String token) {
        try {
            DecodedJWT decodedJWT = JWT.decode(token);
            String username = decodedJWT.getSubject();
            String[] authStrings = decodedJWT.getClaim("auth").asArray(String.class);
            Collection<? extends GrantedAuthority> authorities = Arrays.stream(authStrings)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            UserDetails userDetails = new User(username, "", authorities);

            return new UsernamePasswordAuthenticationToken(userDetails, "", authorities);
        } catch (Exception e) {
            log.error(e.getLocalizedMessage());
            return null;
        }
    }

    public boolean validateToken(String token) {
        try {
            JWTVerifier verifier = JWT.require(algorithm).build();
            verifier.verify(token);
            return true;
        } catch (JWTVerificationException e) {
            return false;
        }
    }
}

// File: scg/src/main/java/com/sc/scg/config/SecurityConfig.java
// SecurityConfig.java
package com.sc.scg.config;

import com.sc.scg.filter.auth.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    //@Value("${allowedOrigins}")
    private String allowedOrigins="http://localhost:3000";

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .cors(cors -> cors
                        .configurationSource(corsConfigurationSource())
                )
                .authorizeExchange(exchanges -> exchanges
                        .matchers(new PathPatternParserServerWebExchangeMatcher("/actuator/**")).permitAll()
                        .matchers(new PathPatternParserServerWebExchangeMatcher("/api/auth/**")).permitAll()
                        .anyExchange().authenticated()
                )
                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

    @Bean
    protected CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}

// File: scg/src/main/java/com/sc/scg/filter/logger/PostLogger.java
package com.sc.scg.filter.logger;

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

@Component
public class PostLogger extends AbstractGatewayFilterFactory<PostLogger.Config> {
    private static final Logger log = LoggerFactory.getLogger(PostLogger.class);

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


// File: scg/src/main/java/com/sc/scg/filter/logger/PreLogger.java
package com.sc.scg.filter.logger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;
import org.springframework.web.server.ServerWebExchange;

@Component
public class PreLogger extends AbstractGatewayFilterFactory<PreLogger.Config> {
    private final Logger log = LoggerFactory.getLogger(getClass());

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

// File: scg/src/main/java/com/sc/scg/filter/auth/JwtAuthenticationFilter.java
// JwtAuthenticationFilter.java
package com.sc.scg.filter.auth;

import com.sc.scg.jwt.JwtTokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter implements WebFilter {
    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    @NonNull
    public Mono<Void> filter(ServerWebExchange exchange, @NonNull WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String token = resolveToken(request);

        if (token != null && jwtTokenProvider.validateToken(token)) {
            return chain.filter(exchange);
        } else {
            return onError(exchange);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }

    private String resolveToken(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}

// File: /Users/ondal/workspace/sc/settings.gradle
rootProject.name = 'sc'
include 'config'
include 'eureka'
include 'scg'



// File: /Users/ondal/workspace/sc/build.gradle
plugins {
	id 'java'
	id 'org.springframework.boot' version '3.2.6'
	id 'io.spring.dependency-management' version '1.1.5'
}

allprojects {
	group = 'com.cna'
	version = '0.0.1-SNAPSHOT'

	apply plugin: 'java'
	apply plugin: 'io.spring.dependency-management'

	java {
		sourceCompatibility = '17'
	}

	repositories {
		mavenCentral()
	}

	dependencies {
		implementation 'org.springframework.boot:spring-boot-starter'

		testImplementation 'org.springframework.boot:spring-boot-starter-test'
		testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
	}

	dependencyManagement {
		imports {
			mavenBom "org.springframework.cloud:spring-cloud-dependencies:2023.0.2"
		}
	}

	tasks.named('test') {
		useJUnitPlatform()
	}
}

subprojects {
	apply plugin: 'org.springframework.boot'
}



