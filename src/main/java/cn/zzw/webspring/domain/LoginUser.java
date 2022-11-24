package cn.zzw.webspring.domain;

import cn.zzw.webspring.domain.entity.Roles;
import cn.zzw.webspring.domain.entity.User;
import com.alibaba.fastjson.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @BelongsProject: WebSpring
 * @BelongsPackage: cn.zzw.webspring.domain
 * @Author: zzw
 * @CreateTime: 2022-11-23  10:14
 * @Description: TODO
 * @Version: 1.0
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginUser implements UserDetails {
    private User user;

    private List<String> perms;

    public LoginUser(User user,List<String> perms) {
        this.user = user;
        this.perms = perms;
    }


    List<SimpleGrantedAuthority> newList = new ArrayList<SimpleGrantedAuthority>();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        for (String perm : perms) {
            SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(perm);
            newList.add(simpleGrantedAuthority);
        }

        return newList;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
