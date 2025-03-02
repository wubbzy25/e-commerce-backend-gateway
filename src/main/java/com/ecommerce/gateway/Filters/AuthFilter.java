package com.ecommerce.gateway.Filters;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
public class AuthFilter implements GlobalFilter {

    private final RestTemplate restTemplate;

    public AuthFilter(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();
        List<String> publicEndPoints = List.of("/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/validate");
        boolean isPublic = publicEndPoints.stream().anyMatch(path::matches);
        if (isPublic) {
            return chain.filter(exchange);
        }

        String token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (token == null || !token.startsWith("Bearer ")) {
            return buildErrorResponse(exchange, "Authorization token is missing or does not start with 'Bearer'");
        }

        String finalToken = token.substring(7); // Remove "Bearer " prefix
        try {
            Boolean isValid = restTemplate.exchange(
                    "http://localhost:8060/api/v1/auth/validate/{token}",
                    HttpMethod.GET,
                    null,
                    Boolean.class,
                    finalToken
            ).getBody();

            if (Boolean.TRUE.equals(isValid)) {
                return chain.filter(exchange);
            } else {
                return buildErrorResponse(exchange, "Token is invalid or expired. Please provide a valid token.");
            }
        } catch (Exception e) {
            return buildErrorResponse(exchange, "An error occurred while validating the token. Please try again.");
        }
    }

    private Mono<Void> buildErrorResponse(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");
        byte[] bytes = String.format("{\"error\": \"%s\"}", message).getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                .bufferFactory().wrap(bytes)));
    }
}
