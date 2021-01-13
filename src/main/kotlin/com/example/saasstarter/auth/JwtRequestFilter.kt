package com.example.saasstarter.auth

import com.example.saasstarter.auth.AuthenticationConstants.ACCESS_TOKEN_PARAM
import com.example.saasstarter.auth.AuthenticationConstants.AUTHORITIES_KEY
import com.example.saasstarter.auth.AuthenticationConstants.HEADER_STRING
import com.example.saasstarter.auth.AuthenticationConstants.TOKEN_PREFIX
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import mu.KotlinLogging
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.web.filter.OncePerRequestFilter
import java.nio.charset.StandardCharsets
import java.util.*
import java.util.stream.Collectors
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JwtRequestFilter(
    private val jwtSecret: String,
) : OncePerRequestFilter() {
    private val klogger = KotlinLogging.logger {}

    override fun doFilterInternal(req: HttpServletRequest, res: HttpServletResponse, chain: FilterChain) {
        val headerToken = req.getHeader(HEADER_STRING)
        klogger.debug { "Header token $headerToken, uri: ${req.requestURI}" }
        if (headerToken != null && !headerToken.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(req, res)
            return
        }

        val token: String? = headerToken?.replace(TOKEN_PREFIX, "")
            ?: req.getParameter(ACCESS_TOKEN_PARAM)

        klogger.debug { "Token $token, params ${req.parameterMap}" }
        if (token == null) {
            chain.doFilter(req, res)
            return
        }

        val authentication = getAuthentication(token)
        if (authentication == null) {
            chain.doFilter(req, res)
            return
        }

        authentication.details = WebAuthenticationDetailsSource().buildDetails(req)
        SecurityContextHolder.getContext().authentication = authentication
        chain.doFilter(req, res)
    }

    private fun getAuthentication(token: String): UsernamePasswordAuthenticationToken? {
        try {
            val claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.toByteArray(StandardCharsets.UTF_8)))
                .build()
                .parseClaimsJws(token)
                .body
            val user = claims.subject ?: return null
            val authorities: Collection<SimpleGrantedAuthority> = Arrays.stream(
                claims[AUTHORITIES_KEY].toString().split(",").toTypedArray()
            )
                .filter { s: String -> s.isNotEmpty() }
                .map { role: String? -> SimpleGrantedAuthority(role) }
                .collect(Collectors.toList())
            return UsernamePasswordAuthenticationToken(user, "", authorities)
        } catch (e: ExpiredJwtException) {
            klogger.info { "Jwt is expired" }
            return null
        }

    }
}

