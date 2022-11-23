package cn.zzw.webspring.service.Impl;

import cn.zzw.webspring.domain.LoginUser;
import cn.zzw.webspring.domain.entity.User;
import cn.zzw.webspring.mapper.UserMapper;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @BelongsProject: WebSpring
 * @BelongsPackage: cn.zzw.webspring.service.Impl
 * @Author: zzw
 * @CreateTime: 2022-11-23  10:08
 * @Description: 从数据库查询
 * @Version: 1.0
 */

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUsername,s);
        User user = userMapper.selectOne(queryWrapper);
        if (user==null){
            throw new RuntimeException("用户不存在");
        }
        return new LoginUser(user);
    }
}
