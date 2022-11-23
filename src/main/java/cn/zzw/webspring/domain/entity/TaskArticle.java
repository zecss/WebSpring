package cn.zzw.webspring.domain.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.io.Serializable;


/**
 * (TaskArticle)表实体类
 *
 * @author makejava
 * @since 2022-11-22 23:07:37
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class TaskArticle implements Serializable{

    private Long id;

    private Long taskId;

    private Object articleId;

}

