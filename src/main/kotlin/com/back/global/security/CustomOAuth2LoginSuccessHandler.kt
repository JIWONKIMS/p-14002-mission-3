package com.back.global.security

import com.back.domain.member.member.service.MemberService
import com.back.global.rq.Rq
import com.back.standard.extensions.base64Decode
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.stereotype.Component

@Component
class CustomOAuth2LoginSuccessHandler(
    private val memberService: MemberService,
    private val rq: Rq
) : AuthenticationSuccessHandler {
    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        // 일단은 현재 소셜 로그인 한 사람이 3번 회원이라고 가정
        val actor = rq.actorFromDb

        val accessToken = memberService.genAccessToken(actor)

        rq.setCookie("apiKey", actor.apiKey)
        rq.setCookie("accessToken", accessToken)

        val redirectUrl = request.getParameter("state")
            ?.let { encoded ->
                runCatching {
                    encoded.base64Decode()
                }.getOrNull()
            }
            ?.substringBefore('#')
            ?.takeIf { it.isNotBlank() }
            ?: "/"

        // ✅ 최종 리다이렉트
        rq.sendRedirect(redirectUrl)
    }
}
