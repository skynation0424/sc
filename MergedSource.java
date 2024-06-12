// File: scg\build.gradle
﻿dependencies {
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


// File: scg\src\main\java\com\sc\scg\filter\auth\AuthorizationHeaderFilter.java
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
        //log.info("************* Check Authorization");
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if (request.getURI().getPath().startsWith("/api/auth") ||
                    request.getURI().getPath().startsWith("/api/subrecommend/detail")) {
                log.info("*** Skip check authentication: "+request.getURI().getPath());
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

// File: scg\src\main\resources\application.yml
﻿server:
  port: ${SERVER_PORT:19080}
spring:
  application:
    name: scg
  jwt:
    secret: ${JWT_SECRET:8O2HQ13etL2BWZvYOiWsJ5uWFoLi6NBUG8divYVoCgtHVvlk3dqRksMl16toztDUeBTSIuOOPvHIrYq11G2BwQ==}
  # -- Load banancer 설정 : 기본 L/B인 Ribbon비활성화
  cloud.loadbalancer.ribbon.enabled: false

eureka:
  instance:
    hostname: ${HOSTNAME}
    instanceId: ${POD_IP}:${SERVER_PORT}
    preferIpAddress: true
    nonSecurePort: 80
    securePort: 443
    nonSecurePortEnabled: true
    securePortEnabled: false
  client:
    service-url:
      defaultZone: ${EUREKA_SERVERS:http://eureka1.127.0.0.1.nip.io:8761/eureka/,http://eureka2.127.0.0.1.nip.io:8762/eureka/}
    registryFetchIntervalSeconds: 5
    instanceInfoReplicationIntervalSeconds: 5

logging:
  level:
    root: INFO
    org.springframework.cloud.gateway: INFO

# -- Actuator
management:
  endpoints:
    web:
      exposure:
        include: health, info, env, mappings, routes

#========= 라우팅
spring.cloud.gateway:
  # CORS
  globalcors:
    cors-configurations:
      '[/**]':
        allowedOrigins: "https://aaa.bbb.com"
        allowedMethods:
          - GET
      '[/api/**]':
        allowedOrigins:
          - http://localhost:3000
          - ${ALLOWED_ORIGINS:"http://localhost:3000"}
        allowedMethods:
          - GET
          - PUT
          - POST
          - DELETE
          - OPTIONS
        allowedHeaders: "*"
  # Timeout
  httpclient:
    connect-timeout: 1000
    response-timeout: 3000

  # Routing
  # 모든 서비스가 k8s환경에서만 서비스 된다면 Eureka를 안 쓰고 k8s서비스로 L/B하는게 제일 좋음
  # 왜냐하면 k8s서비스의 liveness/readiness 체크하여 연결하는 기능을 사용할 수 있고, 불필요한 Eureka 네트워킹을 안할 수 있기 때문임
  # 이 예제에서는 Eureka에 Pod IP를 등록하고 SCG가 L/B하고 있음. 로그인요청만 Eureka연동하고, 나머지는 k8s서비스 사용함
  routes:
    - id: auth
      uri: lb://member-service
      #uri: http://member:18080
      #uri: http://172.17.0.24:18080
      predicates:
        - Path=/api/auth/**

    - id: member
      uri: http://member:18080
      predicates:
        - Path=/api/members/**

    - id: subrecommend
      uri: http://subrecommend:18081
      predicates:
        - Path=/api/subrecommend/**

    - id: mysub
      uri: http://mysub:18082
      predicates:
        - Path=/api/my-subs/**

    - id: mygrp
      uri: http://mygrp:18083
      predicates:
        - Path=/api/my-groups/**

    - id: transfer
      uri: http://transfer:18084
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
        response-timeout: 3000

  # 그 외 application.yml에 설정 예제는 아래 페이지 참조
  # https://happycloud-lee.tistory.com/218
  #========================

  #========= Default Filters ========
  default-filters:
    #-- 인증 검사: JWT Token 유효성 검사
    - AuthorizationHeaderFilter

    # Request Logging
    - name: PreLogger
      args:
        logging: true
        baseMessage: "######### Logging for Request ############"

    # Response Logging
    - name: PostLogger
      args:
        logging: true
        baseMessage: "######### Logging for Response ############"

    # 중요) 응답에 지정된 헤더가 중복되면 하나만 남김. 다른 필터와의 우선순위로 동작 안할 수 있으므로 가장 마지막에 지정
    - DedupeResponseHeader=Access-Control-Allow-Credentials Access-Control-Allow-Origin
#=====================================



// File: D:\home\ondal\workspace\sc\settings.gradle
rootProject.name = 'sc'
include 'config'
include 'eureka'
include 'scg'



// File: D:\home\ondal\workspace\sc\build.gradle
plugins {
	id 'java'
	id 'org.springframework.boot' version '3.2.6'
	id 'io.spring.dependency-management' version '1.1.5'
	id "org.sonarqube" version "5.0.0.4638" apply false		//apply false 해야 서브 프로젝트에 제대로 적용됨
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
		implementation 'org.springframework.boot:spring-boot-starter-actuator'

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
	apply plugin: 'org.sonarqube'
}



