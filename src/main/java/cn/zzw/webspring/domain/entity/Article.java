package cn.zzw.webspring.domain.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.io.Serializable;


/**
 * (Article)表实体类
 *
 * @author makejava
 * @since 2022-11-22 23:07:36
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Article implements Serializable{

    private Long id;
    //标题
    private String title;

    private String content;

    private Long viewCount;

    private Long goodCount;

}

