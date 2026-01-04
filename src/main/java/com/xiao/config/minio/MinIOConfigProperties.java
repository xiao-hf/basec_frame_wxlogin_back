package com.xiao.config.minio;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.io.Serializable;

@Data
@Component
@ConfigurationProperties(prefix = "minio")  //自动注入属性前缀为minio的配置
public class MinIOConfigProperties implements Serializable {

    private String accessKey; // 访问key
    private String secretKey; // 秘钥
    private String bucket;    // 桶
    private String endpoint;  // 地域节点
    private String dir; // 目录
}