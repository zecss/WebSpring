package cn.zzw.webspring.controller;

import cn.zzw.webspring.domain.entity.User;
import cn.zzw.webspring.domain.result.ResponseResult;
import cn.zzw.webspring.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * @BelongsProject: WebSpring
 * @BelongsPackage: cn.zzw.webspring.controller
 * @Author: zzw
 * @CreateTime: 2022-11-22  23:13
 * @Description: TODO
 * @Version: 1.0
 */
@Api(tags = "关于用户")
@RestController
@RequestMapping("user")
public class UserController {
    @Autowired
    private UserService userService;


    @ApiOperation("用户登录")
    @PostMapping("login")
    public ResponseResult login(@RequestBody User user){
        return userService.login(user);
    }






















}
