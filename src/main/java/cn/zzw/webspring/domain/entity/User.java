package cn.zzw.webspring.domain.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.io.Serializable;


/**
 * (User)表实体类
 *
 * @author makejava
 * @since 2022-11-22 23:07:37
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class User implements Serializable{
    //用户id
    private Long id;
    //用户名
    private String username;
    //密码
    private String password;
    //姓名
    private String name;
    //头像地址
    private String headUrl;
    //描述
    private String description;
    //状态（1：正常 0：停用）
    private Integer status;

}

