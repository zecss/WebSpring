package cn.zzw.webspring.mapper;

import cn.zzw.webspring.domain.entity.Roles;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
 * @BelongsProject: WebSpring
 * @BelongsPackage: cn.zzw.webspring.mapper
 * @Author: zzw
 * @CreateTime: 2022-11-24  11:01
 * @Description: TODO
 * @Version: 1.0
 */
@Mapper
public interface RolesMapper extends BaseMapper<Roles> {
    List<String> selectRoleByUserId(Long id);
}
