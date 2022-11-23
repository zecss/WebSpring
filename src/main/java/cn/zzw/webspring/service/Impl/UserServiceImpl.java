package cn.zzw.webspring.service.Impl;

import cn.zzw.webspring.domain.LoginUser;
import cn.zzw.webspring.domain.entity.User;
import cn.zzw.webspring.domain.result.ResponseResult;
import cn.zzw.webspring.mapper.UserMapper;
import cn.zzw.webspring.service.UserService;
import cn.zzw.webspring.utils.JwtUtil;
import cn.zzw.webspring.utils.RedisCache;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.HashMap;

/**
 * (User)表服务实现类
 *
 * @author makejava
 * @since 2022-11-22 23:07:37
 */
@Service("userService")
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private RedisCache redisCache;

    @Override
    public ResponseResult login(User user) {
        //认证
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        String userId = loginUser.getUser().getId().toString();
        //生成jwt
        String jwt = JwtUtil.createJWT(userId);
        //存入redis
        redisCache.setCacheObject("user"+userId,loginUser);
        return ResponseResult.okResult(jwt);
    }
}

