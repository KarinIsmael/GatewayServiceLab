package com.example.jwtauth.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfiguration {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private com.example.jwtauth.auth.SecurityContextRepository securityContextRepository;

    @Bean
    public SecurityWebFilterChain securitygWebFilterChain(ServerHttpSecurity http) {


        return http.httpBasic().disable()
                .formLogin().disable()
                .csrf().disable()
                .logout().disable()
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authenticationManager(this.authenticationManager)
                .securityContextRepository(this.securityContextRepository)
                .exceptionHandling()
                .authenticationEntryPoint((swe, e) -> Mono.fromRunnable(() ->
                        swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED)
                )).accessDeniedHandler((swe, e) -> Mono.fromRunnable(() ->
                        swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN))).and()
                .authorizeExchange()
                .pathMatchers("/auth/**").permitAll()
                .pathMatchers(HttpMethod.GET,"/pizzas/**").permitAll()
                .anyExchange().hasRole("ADMIN")
                .and().build();
    }
}