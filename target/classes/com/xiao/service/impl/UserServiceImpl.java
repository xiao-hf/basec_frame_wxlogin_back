package com.xiao.service.impl;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.util.IdUtil;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.xiao.common.AjaxResult;
import com.xiao.common.constants.RedisPrefix;
import com.xiao.common.enums.RoleEnum;
import com.xiao.common.dto.RoleDto;
import com.xiao.common.dto.UserDto;
import com.xiao.dao.Permission;
import com.xiao.dao.Role;
import com.xiao.dao.RolePermission;
import com.xiao.dao.User;
import com.xiao.dao.UserRole;
import com.xiao.http.req.ReqWxLogin;
import com.xiao.mapper.PermissionMapper;
import com.xiao.mapper.RoleMapper;
import com.xiao.mapper.RolePermissionMapper;
import com.xiao.mapper.UserMapper;
import com.xiao.mapper.UserRoleMapper;
import com.xiao.service.UserService;
import com.xiao.utils.JwtUtil;
import com.xiao.utils.MyUtil;
import com.xiao.utils.RedisUtil;
import com.xiao.utils.SecurityUtil;
import jakarta.annotation.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class UserServiceImpl implements UserService {

    private static final Logger log = LoggerFactory.getLogger(UserServiceImpl.class);
    @Resource
    UserMapper userMapper;

    @Resource
    RedisUtil redisUtil;

    @Resource
    RoleMapper roleMapper;

    @Resource
    UserRoleMapper userRoleMapper;

    @Resource
    RolePermissionMapper rolePermissionMapper;

    @Resource
    PermissionMapper permissionMapper;

    @Override
    public AjaxResult<String> geneCode(String phone) {
        String code = MyUtil.randomNumStr(6);
        redisUtil.set(RedisPrefix.LOGIN_CODE + phone, code, 5, TimeUnit.MINUTES);

        // todo 发送验证码短信...

        log.info("手机{} 用户 验证码{}", phone, code);
        return AjaxResult.success("验证码已生成, 有效期5分钟!");
    }

    @Override
    public AjaxResult<String> login(ReqWxLogin req) {
        Date now = new Date();
        String openId = req.getOpenId();

        User user = userMapper.selectOne(
            Wrappers.<User>lambdaQuery()
                .eq(User::getWxOpenId, openId)
                .last("LIMIT 1")
        );

        // 1) 不存在则创建用户，并分配 USER 角色
        if (user == null) {
            user = createWxUser(openId, now);
            assignUserRoleIfAbsent(user.getId(), now);
        } else if (Boolean.TRUE.equals(user.getIsDeleted())) {
            user.setIsDeleted(false);
            user.setUpdateTime(now);
            userMapper.updateById(user);
        }

        if (!Boolean.TRUE.equals(user.getEnable())) {
            return AjaxResult.error("用户未启用");
        }

        String preToken = user.getToken();
        Long userId = user.getId();

        // 2) 封装 UserDto 并加载角色权限
        UserDto userDto = BeanUtil.copyProperties(user, UserDto.class);
        List<UserRole> userRoles = userRoleMapper.selectList(
            Wrappers.<UserRole>lambdaQuery().eq(UserRole::getUserId, userId)
        );
        if (userRoles.isEmpty()) {
            assignUserRoleIfAbsent(userId, now);
            userRoles = userRoleMapper.selectList(
                Wrappers.<UserRole>lambdaQuery().eq(UserRole::getUserId, userId)
            );
        }
        if (userRoles.isEmpty()) {
            return AjaxResult.error("用户角色缺失");
        }
        UserRole userRole = userRoles.get(0);
        Long roleId = userRole.getRoleId();
        Role role = roleMapper.selectById(roleId);
        if (role == null) {
            return AjaxResult.error("用户角色不存在");
        }
        RoleDto roleDto = BeanUtil.copyProperties(role, RoleDto.class);
        List<RolePermission> rolePermissions = rolePermissionMapper.selectList(
            Wrappers.<RolePermission>lambdaQuery().eq(RolePermission::getRoleId, roleId)
        );
        List<Permission> permissions = new ArrayList<>();
        for (RolePermission rolePermission : rolePermissions) {
            Long permissionId = rolePermission.getPermissionId();
            Permission permission = permissionMapper.selectById(permissionId);
            if (permission != null) {
                permissions.add(permission);
            }
        }
        roleDto.setPermissions(permissions);
        userDto.setRoleDto(roleDto);
        String token = IdUtil.randomUUID();
        userDto.setToken(token);

        // 3) 更新数据库 user token 和登录时间
        user.setToken(token);
        user.setLastLoginTime(now);
        user.setUpdateTime(now);
        userMapper.updateById(user);
        userDto.setLastLoginTime(now);
        userDto.setUpdateTime(now);

        // 4) 生成 token：authorization -> token -> UserDto
        String authorization = JwtUtil.geneAuth(userDto);
        String key = RedisPrefix.LOGIN_TOKEN + token;
        redisUtil.set(key, userDto);

        // 5) 设置 UserDto 到 Security 上下文
        SecurityUtil.setUser(userDto);

        // 6) 清理之前登录缓存
        if (preToken != null && !preToken.isBlank()) {
            redisUtil.del(RedisPrefix.LOGIN_TOKEN + preToken);
        }
        return AjaxResult.success(authorization);
    }

    @Override
    public AjaxResult<String> logout() {
        String token = SecurityUtil.getToken();
        String key = RedisPrefix.LOGIN_TOKEN + token;
        redisUtil.del(key);
        return AjaxResult.success("退出成功!");
    }

    private User createWxUser(String openId, Date now) {
        User user = new User();
        user.setWxOpenId(openId);
        user.setUsername(buildWxUsername(openId));
        user.setPassword(IdUtil.randomUUID());
        user.setRealName("");
        user.setUnitId(0L);
        user.setEnable(true);
        user.setCreateTime(now);
        user.setUpdateTime(now);
        user.setIsDeleted(false);
        userMapper.insert(user);
        return user;
    }

    private String buildWxUsername(String openId) {
        String username = "wx_" + openId;
        return username.length() <= 50 ? username : username.substring(0, 50);
    }

    private void assignUserRoleIfAbsent(Long userId, Date now) {
        long exists = userRoleMapper.selectCount(
            Wrappers.<UserRole>lambdaQuery().eq(UserRole::getUserId, userId)
        );
        if (exists > 0) {
            return;
        }

        Role userRoleEntity = roleMapper.selectOne(
            Wrappers.<Role>lambdaQuery().eq(Role::getRoleCode, RoleEnum.USER.getCode())
        );
        if (userRoleEntity == null) {
            return;
        }

        UserRole relation = new UserRole();
        relation.setUserId(userId);
        relation.setRoleId(userRoleEntity.getId());
        relation.setCreateTime(now);
        userRoleMapper.insert(relation);
    }
}
