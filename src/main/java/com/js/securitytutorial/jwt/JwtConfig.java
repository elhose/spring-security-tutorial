package com.js.securitytutorial.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpHeaders;

@ConfigurationProperties(prefix = "application.jwt")
public class JwtConfig {

    private String secretKey;
    private String tokenPrefix;
    private Integer tokeExpirationAfterDays;

    public JwtConfig() {
    }

    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }

    public Integer getTokeExpirationAfterDays() {
        return tokeExpirationAfterDays;
    }

    public void setTokeExpirationAfterDays(Integer tokeExpirationAfterDays) {
        this.tokeExpirationAfterDays = tokeExpirationAfterDays;
    }
}
