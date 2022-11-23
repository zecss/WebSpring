package cn.zzw.webspring.service;

import cn.zzw.webspring.domain.entity.User;
import cn.zzw.webspring.domain.result.ResponseResult;
import com.baomidou.mybatisplus.extension.service.IService;


/**
 * (User)表服务接口
 *
 * @author makejava
 * @since 2022-11-22 23:07:37
 */
public interface UserService extends IService<User> {

    ResponseResult login(User user);
}

