package com.subride.sc.scg.filter.logger;

import lombok.extern.slf4j.Slf4j;
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
