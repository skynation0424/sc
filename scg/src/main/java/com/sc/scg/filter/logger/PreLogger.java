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