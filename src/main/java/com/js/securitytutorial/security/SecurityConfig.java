package com.js.securitytutorial.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.js.securitytutorial.security.ApplicationUserPermission.*;
import static com.js.securitytutorial.security.ApplicationUserRole.*;

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
            .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
            .antMatchers("/api/**").hasAnyRole(STUDENT.name())
            .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
            .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
            .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
            .antMatchers(HttpMethod.GET, "/management/api/**").hasAuthority(COURSE_READ.getPermission())
            .anyRequest()
            .authenticated()
            .and()
            .httpBasic();
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
