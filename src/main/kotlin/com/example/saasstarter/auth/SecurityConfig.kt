package com.example.saasstarter.auth

import com.example.heyday.services.StudentUserDetailsServiceImpl
import com.example.heyday.services.TeacherUserDetailsServiceImpl
import io.jsonwebtoken.Jwt
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

fun commonConfiguration(http: HttpSecurity?, userType: String) = http
        ?.antMatcher("/$userType/**")
        ?.authorizeRequests()
        ?.antMatchers("/",
                "/teacher/confirm-account",
                "/student/confirm-account",
                "/teacher/login",
                "/teacher/register",
                "/student/login",
                "/student/register",
                "/js/**",
                "/css/**",
                "/img/**",
                "/webjars/**",
                "/favicon.ico")?.permitAll()
        ?.anyRequest()
        ?.authenticated()

        ?.and()
        ?.formLogin()
        ?.failureHandler(FailureLoginHandler(userType))
        ?.loginPage("/$userType/login")
        ?.loginProcessingUrl("/$userType/login")
        ?.defaultSuccessUrl("/$userType/home")
        ?.usernameParameter("email")

        ?.and()
        ?.logout()
        ?.logoutSuccessUrl("/")
        ?.deleteCookies("JSESSIONID")

        ?.and()
        ?.exceptionHandling()
        ?.accessDeniedPage("/403")

@Configuration
@EnableWebSecurity
class SecurityConfig : WebSecurityConfigurerAdapter() {
    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    override fun configure(http: HttpSecurity?) {
        http?.authorizeRequests()?.antMatchers(
                "/",
                "/teacher/confirm-account",
                "/student/confirm-account",
                "/teacher/login",
                "/teacher/register",
                "/student/login",
                "/student/register",
                "/js/**",
                "/css/**",
                "/img/**",
                "/webjars/**",
                "/favicon.ico"
        )?.permitAll()
                ?.and()
                ?.logout()
                ?.logoutSuccessUrl("/")
    }

    @Configuration
    @Order(1)
    class TeacherSecurityConfig(
            @Autowired private val teacherUserDetailsServiceImpl: TeacherUserDetailsServiceImpl,
    ) : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity?) {
            commonConfiguration(http, "teacher")
        }

        override fun configure(auth: AuthenticationManagerBuilder) {
            auth.userDetailsService(teacherUserDetailsServiceImpl)
        }
    }

    @Configuration
    @Order(2)
    class StudentSecurityConfig(
            @Autowired private val studentUserDetailsServiceImpl: StudentUserDetailsServiceImpl,
    ) : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity?) {
            commonConfiguration(http, "student")
        }

        override fun configure(auth: AuthenticationManagerBuilder) {
            auth.userDetailsService(studentUserDetailsServiceImpl)
        }
    }

    @Configuration
    @Order(3)
    class APISecurityConfig(
            @Autowired private val studentUserDetailsServiceImpl: StudentUserDetailsServiceImpl,
            @Autowired private val passwordEncoder: PasswordEncoder,
            @Value("\${jwt.secret}") private val jwtSecret: String,
    ) : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            val jwtRequestFilter = JwtRequestFilter(jwtSecret)
            http.antMatcher("/api/**")
                    .authorizeRequests()
                        .antMatchers("/api/hello").permitAll()
                        .antMatchers(HttpMethod.POST, "/api/student/authenticate").permitAll()
                        .antMatchers(HttpMethod.GET, "/api/student/refresh").permitAll()
                        .anyRequest().authenticated()
                    .and()
                        .csrf()
                        .disable()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                    .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter::class.java)
        }
        
        override fun configure(auth: AuthenticationManagerBuilder) {
            auth.userDetailsService(studentUserDetailsServiceImpl)
                    .passwordEncoder(passwordEncoder)
        }

        @Bean
        fun corsConfigurationSource(): CorsConfigurationSource? {
            val source = UrlBasedCorsConfigurationSource()
            source.registerCorsConfiguration("/**", CorsConfiguration().applyPermitDefaultValues())
            return source
        }
    }

}