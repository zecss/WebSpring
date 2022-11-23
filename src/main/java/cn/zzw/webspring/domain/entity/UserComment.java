package cn.zzw.webspring.domain.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.io.Serializable;


/**
 * (UserComment)表实体类
 *
 * @author makejava
 * @since 2022-11-22 23:07:37
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserComment implements Serializable{

    private Long id;

    private Long userId;

    private Long commentId;

}

