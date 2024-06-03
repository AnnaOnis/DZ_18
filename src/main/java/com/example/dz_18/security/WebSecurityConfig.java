package com.example.dz_18.config;

import com.example.dz_18.security.repositories.UserRepository;
import com.example.dz_18.security.securityUser.UserDetailsServiceImplementation;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeHttpRequests()
                .antMatchers("/", "/s/gen", "/register").permitAll()
//                .requestMatchers(new AntPathRequestMatcher("/register", "GET")).permitAll()
//                .requestMatchers(new AntPathRequestMatcher("/register", "POST")).hasRole("ROLE_ANONYMOUS")
                .antMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/profile")
                .and()
                .logout()
//                .logoutUrl("/logout") // строка идентична следующей строке
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .clearAuthentication(true)
                .logoutSuccessUrl("/auth/login");
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers("/styles/*.css");
    }

    @Bean
    protected BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    protected DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(encoder());
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }
}
//public class WebSecurityConfig {
//
//    private final DataSource dataSource;
//    private final UserRepository repo;
//
//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//        return (web) -> web.ignoring()
//                .requestMatchers("/styles/*.css");
//    }
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests((requests) -> requests
//                        .requestMatchers("/").permitAll()
//                        .requestMatchers("/register").hasRole("ROLE_ANONYMOUS")
//                        .requestMatchers("/logout", "/profile").hasAnyRole("ADMIN", "USER")
//                )
//                .formLogin(form -> form
//                        .loginPage("/login").permitAll()
//                )
//                .logout((form) -> form
//                        .logoutUrl("/logout")
//                );
//        return http.build();
//    }
//
//    @Bean
//    protected PasswordEncoder encoder() {
//        return new BCryptPasswordEncoder(12);
//    }
//
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        return new UserDetailsServiceImplementation(repo);
//    }
//
//    @Bean
//    protected DaoAuthenticationProvider daoAuthenticationProvider() {
//        DaoAuthenticationProvider dap = new DaoAuthenticationProvider();
//        dap.setUserDetailsService(userDetailsService());
//        dap.setPasswordEncoder(encoder());
//        return dap;
//    }
//
//
//    @Bean
//    public UserDetailsManager userDetailsManager(HttpSecurity http) throws Exception {
//        AuthenticationManager authManager = http
//                .getSharedObject(AuthenticationManagerBuilder.class)
//                .userDetailsService(userDetailsService())
//                .passwordEncoder(encoder())
//                .and()
//                .authenticationProvider(daoAuthenticationProvider()) //
//                .build();
//        JdbcUserDetailsManager jdbcManager = new JdbcUserDetailsManager(dataSource);
//        jdbcManager.setAuthenticationManager(authManager);
//        return jdbcManager;
//    }
//
//}
