package cn.zzw.webspring.filter;

import cn.zzw.webspring.domain.LoginUser;
import cn.zzw.webspring.domain.entity.User;
import cn.zzw.webspring.domain.result.AppHttpCodeEnum;
import cn.zzw.webspring.exception.SystemException;
import cn.zzw.webspring.utils.JwtUtil;
import cn.zzw.webspring.utils.RedisCache;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @BelongsProject: WebSpring
 * @BelongsPackage: cn.zzw.webspring.filter
 * @Author: zzw
 * @CreateTime: 2022-11-23  15:19
 * @Description: TODO
 * @Version: 1.0
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    @Autowired
    private RedisCache redisCache;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader("token");
        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }
        //    解析token
        String userId = null;
        try {
            Claims claims = JwtUtil.parseJWT(token);
            userId = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            throw new SystemException(AppHttpCodeEnum.NEED_LOGIN);
        }
        //    redis获取
        LoginUser loginUser = redisCache.getCacheObject("user" + userId);
        if (loginUser==null){
            throw new SystemException(AppHttpCodeEnum.NEED_LOGIN);
        }
        //   存入Context
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginUser, null, null);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(request,response);

    }
}
