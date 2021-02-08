package com.js.securitytutorial.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    public SecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/", "index", "/css/*", "/js/*")
            .permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails student = User.builder()
                                      .username("John")
                                      .password(passwordEncoder.encode("password"))
                                      .roles(ApplicationUserRole.STUDENT.name()) //ROLE_STUDENT
                                      .build();

        UserDetails admin = User.builder()
                                .username("Tom")
                                .password(passwordEncoder.encode("password123"))
                                .roles(ApplicationUserRole.ADMIN.name()) //ROLE_ADMIN
                                .build();
        return new InMemoryUserDetailsManager(student, admin);
    }
}
