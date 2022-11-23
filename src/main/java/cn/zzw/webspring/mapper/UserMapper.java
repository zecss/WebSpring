package cn.zzw.webspring.mapper;

import cn.zzw.webspring.domain.entity.User;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

/**
 * (User)表数据库访问层
 *
 * @author makejava
 * @since 2022-11-22 23:07:37
 */
@Mapper
public interface UserMapper extends BaseMapper<User> {

}

