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
@TableName(value = "app_img")
public class AppImg {
    /**
     * 主键
     */
    @TableId(value = "id", type = IdType.AUTO)
    @Schema(description = "主键")
    private Long id;

    /**
     * 小程序id
     */
    @TableField(value = "app_id")
    @Schema(description = "小程序id")
    private String appId;

    /**
     * 小程序名字
     */
    @TableField(value = "`name`")
    @Schema(description = "小程序名字")
    private String name;

    /**
     * 创建时间
     */
    @TableField(value = "create_time")
    @Schema(description = "创建时间")
    private Date createTime;

    /**
     * 修改时间
     */
    @TableField(value = "update_time")
    @Schema(description = "修改时间")
    private Date updateTime;

    /**
     * 企业微信图片
     */
    @TableField(value = "wx_img")
    @Schema(description = "企业微信图片")
    private String wxImg;
}