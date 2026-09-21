package com.example.demo.config;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WebAuthnConfig {

    @Bean
    public ObjectConverter objectConverter() {
        return new ObjectConverter();
    }

    @Bean
    public WebAuthnManager webAuthnManager(ObjectConverter objectConverter) {
        return WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    }
}