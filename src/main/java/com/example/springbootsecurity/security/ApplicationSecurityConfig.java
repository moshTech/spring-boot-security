package com.example.springbootsecurity.security;

import static com.example.springbootsecurity.security.ApplicationUserPermission.COURSE_WRITE;
import static com.example.springbootsecurity.security.ApplicationUserRole.ADMIN;
import static com.example.springbootsecurity.security.ApplicationUserRole.ADMINTRAINING;
import static com.example.springbootsecurity.security.ApplicationUserRole.STUDENT;

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

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{
    
    private final PasswordEncoder passwordEncoder;


    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
        .csrf().disable()
        .authorizeRequests()
        .antMatchers("/","index", "/css/*", "/js/*")
        .permitAll()
        .antMatchers("/api/**").hasRole(STUDENT.name())
        .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
        .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
        .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
        .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMINTRAINING.name(), ADMIN.name())
        .anyRequest()
        .authenticated()
        .and()
        .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService(){
        UserDetails mosh = User.builder()
        .username("mosh")
        .password(passwordEncoder.encode("password"))
        // .roles(STUDENT.name())
        .authorities(STUDENT.getGrantedAuthorities())
        .build();

        UserDetails abiola = User.builder()
        .username("abiola")
        .password(passwordEncoder.encode("password"))
        // .roles(ADMIN.name())
        .authorities(ADMIN.getGrantedAuthorities())
        .build();

        UserDetails adegoke = User.builder()
        .username("adegoke")
        .password(passwordEncoder.encode("password"))
        // .roles(ADMINTRAINING.name())
        .authorities(ADMINTRAINING.getGrantedAuthorities())
        .build();

        return new InMemoryUserDetailsManager(
            mosh,
            abiola,
            adegoke
        );
    }
}
