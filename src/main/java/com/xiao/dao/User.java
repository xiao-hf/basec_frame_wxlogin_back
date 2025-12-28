package com.xiao.dao;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Date;
import lombok.Data;

@Schema
@Data
@TableName(value = "`user`")
public class User {
    @TableId(value = "id", type = IdType.AUTO)
    @Schema(description = "")
    private Long id;

    /**
     * 登录用户名
     */
    @TableField(value = "username")
    @Schema(description = "登录用户名")
    private String username;

    /**
     * 密码
     */
    @TableField(value = "`password`")
    @Schema(description = "密码")
    private String password;

    /**
     * 真实姓名
     */
    @TableField(value = "real_name")
    @Schema(description = "真实姓名")
    private String realName;

    /**
     * 所属部门/单位ID
     */
    @TableField(value = "unit_id")
    @Schema(description = "所属部门/单位ID")
    private Long unitId;

    /**
     * 职位
     */
    @TableField(value = "`position`")
    @Schema(description = "职位")
    private String position;

    /**
     * 身份证号
     */
    @TableField(value = "id_card")
    @Schema(description = "身份证号")
    private String idCard;

    /**
     * 性别：0-女，1-男
     */
    @TableField(value = "gender")
    @Schema(description = "性别：0-女，1-男")
    private Integer gender;

    /**
     * 联系电话
     */
    @TableField(value = "phone")
    @Schema(description = "联系电话")
    private String phone;

    /**
     * 电子邮箱
     */
    @TableField(value = "email")
    @Schema(description = "电子邮箱")
    private String email;

    /**
     * 头像URL
     */
    @TableField(value = "avatar")
    @Schema(description = "头像URL")
    private String avatar;

    /**
     * 是否启用
     */
    @TableField(value = "`enable`")
    @Schema(description = "是否启用")
    private Boolean enable;

    /**
     * 创建时间
     */
    @TableField(value = "create_time")
    @Schema(description = "创建时间")
    private Date createTime;

    /**
     * 更新时间
     */
    @TableField(value = "update_time")
    @Schema(description = "更新时间")
    private Date updateTime;

    /**
     * 最后登录时间
     */
    @TableField(value = "last_login_time")
    @Schema(description = "最后登录时间")
    private Date lastLoginTime;

    /**
     * 是否删除
     */
    @TableField(value = "is_deleted")
    @Schema(description = "是否删除")
    private Boolean isDeleted;

    /**
     * 登陆成功token
     */
    @TableField(value = "token")
    @Schema(description = "登陆成功token")
    private String token;

    /**
     * 微信登录的openId
     */
    @TableField(value = "wx_open_id")
    @Schema(description = "微信登录的openId")
    private String wxOpenId;
}