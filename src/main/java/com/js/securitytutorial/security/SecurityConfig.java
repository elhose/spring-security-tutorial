package com.js.securitytutorial.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.js.securitytutorial.security.ApplicationUserPermission.*;
import static com.js.securitytutorial.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    public SecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//            .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//            .and()
            .csrf().disable()
            .authorizeRequests()
            .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
            .antMatchers("/api/**").hasAnyRole(STUDENT.name())
            .anyRequest()
            .authenticated()
            .and()
            .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/courses", true)
                .usernameParameter("user-param")
                .passwordParameter("pass-param")
            .and()
            .rememberMe()
                .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                .key("something-very-secure")
                .rememberMeParameter("remember-param")
            .and()
            .logout()
                .logoutUrl("/logout")
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "remember-me")
                .logoutSuccessUrl("/login");
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails student = User.builder()
                                  .username("Jim")
                                  .password(passwordEncoder.encode("password"))
//                                  .roles(STUDENT.name()) //ROLE_STUDENT
                                  .authorities(STUDENT.getGrantedAuthorities())
                                  .build();

        UserDetails admin = User.builder()
                                .username("Michael")
                                .password(passwordEncoder.encode("password123"))
//                                .roles(ADMIN.name()) //ROLE_ADMIN
                                .authorities(ADMIN.getGrantedAuthorities())
                                .build();

        UserDetails adminTrainee = User.builder()
                                       .username("Dwight")
                                       .password(passwordEncoder.encode("password123456"))
//                                .roles(ADMIN_TRAINEE.name()) //ROLE_ADMINTRAINEE
                                       .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
                                       .build();
        return new InMemoryUserDetailsManager(student, admin, adminTrainee);
    }
}
