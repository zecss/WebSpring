package cn.zzw.webspring.domain.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.io.Serializable;


/**
 * (Comment)表实体类
 *
 * @author makejava
 * @since 2022-11-22 23:07:36
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Comment implements Serializable{

    private Long id;

    private String comment;

}

