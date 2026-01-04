package com.xiao.utils;

import cn.hutool.core.util.IdUtil;
import cn.hutool.http.Method;
import com.alibaba.fastjson.JSON;
import com.xiao.config.minio.MinIOConfigProperties;
import io.minio.*;
import io.minio.messages.Item;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
public class MinioUtil {

    @Resource
    private MinioClient minioClient;

    private static final String separator = "/";

    @Resource
    MinIOConfigProperties minIOConfigProperties;

    /**
     * 批量插入, 返回JSON url集合字符串
     * @param files
     * @return
     */
    public String uploadBatch(String bucket, String dir, MultipartFile[] files) {
        List<String> urls = new ArrayList<>();
        for (MultipartFile file : files)
            urls.add(uploadFile(bucket, dir, file));
        return JSON.toJSONString(urls);
    }

    public void deleteFileByPresignedUrl(String presignedUrl) {
        try {
            // 移除查询参数
            String urlWithoutQuery = presignedUrl.split("\\?")[0];
            // 解析 URL
            URL url = new URL(urlWithoutQuery);
            String path = url.getPath();
            // 移除开头的斜杠
            if (path.startsWith("/")) {
                path = path.substring(1);
            }
            // 提取桶名和对象名
            int firstSlash = path.indexOf('/');
            if (firstSlash > 0) {
                String bucketName = path.substring(0, firstSlash);
                String objectName = path.substring(firstSlash + 1);
                // URL 解码对象名
                objectName = URLDecoder.decode(objectName, StandardCharsets.UTF_8);
                // 使用 MinIO 客户端删除对象
                minioClient.removeObject(
                        RemoveObjectArgs.builder()
                                .bucket(bucketName)
                                .object(objectName)
                                .build()
                );
                // 检查桶是否为空，如果为空则删除桶
                List<String> remainingObjects = listObjects(bucketName);
                if (remainingObjects.isEmpty()) {
                    removeBucket(bucketName);
                }
            } else {
                log.error("无法从 URL 中提取桶名和对象名: {}", presignedUrl);
            }
        } catch (Exception e) {
            log.error("删除文件失败: {}", presignedUrl, e);
        }
    }

    public boolean containsBucket(String bucketName) {
        try {
            return minioClient.bucketExists(BucketExistsArgs.builder().bucket(bucketName).build());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // 删除文件
    public void removeObject(String buckName, String filePath) {
        try {
            minioClient.removeObject(RemoveObjectArgs.builder()
                    .bucket(buckName)
                    .object(filePath)
                    .build());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // 获取桶内文件名集合
    public List<String> listObjects(String bucketName) {
        Iterable<Result<Item>> res = minioClient.listObjects(ListObjectsArgs.builder().bucket(bucketName).build());
        List<String> ans = new ArrayList<>();
        res.forEach(itemResult -> {
            try {
                Item item = itemResult.get();
                ans.add(item.objectName());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        return ans;
    }

    // 把文件写入磁盘
    public void transfer(String bucketName, String filePath, String targetDir) {
        try {
            minioClient.getObject(GetObjectArgs.builder()
                            .bucket(bucketName)
                            .object(filePath)
                            .build())
                    .transferTo(Files.newOutputStream(Paths.get(targetDir)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // 获取文件的字节数组
    public byte[] getFile(String bucketName, String filePath) {
        try {
            return minioClient.getObject(GetObjectArgs.builder()
                    .bucket(bucketName)
                    .object(filePath)
                    .build()).readAllBytes();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // 获取文件的url
    public String getObjUrl(String bucketName, String filePath, Method method) {
        return minIOConfigProperties.getEndpoint() + separator + bucketName + separator + filePath;
    }

    /**
     * 替换URL中的编码文件名为原始文件名
     * @param encodedUrl 包含编码文件名的URL
     * @param originalFileName 原始文件名（包含扩展名，如"合照.png"）
     * @return 替换后的URL
     */
    public String replaceEncodedFileNameWithOriginal(String encodedUrl, String originalFileName) {
        try {
            // 获取文件名部分（不含扩展名）和扩展名
            String fileName = originalFileName;
            String extension = "";
            if (originalFileName.contains(".")) {
                int dotIndex = originalFileName.lastIndexOf(".");
                fileName = originalFileName.substring(0, dotIndex);
                extension = originalFileName.substring(dotIndex); // 包含点号
            }

            // 对文件名进行URL编码
            String encodedFileName = URLEncoder.encode(fileName, StandardCharsets.UTF_8.toString());
            // 编码后的扩展名，如果有的话
            String encodedExtension = extension.isEmpty() ? "" :
                    URLEncoder.encode(extension, StandardCharsets.UTF_8.toString());
            // 完整的编码文件名
            String fullEncodedFileName = encodedFileName + encodedExtension;

            // 查询参数开始的位置
            int queryParamIndex = encodedUrl.indexOf("?");
            if (queryParamIndex < 0) {
                return encodedUrl; // 如果URL没有查询参数，直接返回
            }

            // 分离基础URL和查询参数
            String baseUrl = encodedUrl.substring(0, queryParamIndex);
            String queryParams = encodedUrl.substring(queryParamIndex);

            // 尝试找到编码的文件名在URL中的位置
            int fileNameStartIndex = baseUrl.lastIndexOf("/") + 1;
            String path = baseUrl.substring(0, fileNameStartIndex);

            // 直接构造新的URL
            return path + originalFileName + queryParams;
        } catch (Exception e) {
            throw new RuntimeException("替换文件名时出错", e);
        }
    }

    public String uploadFileByContent(String bucket, String dir, String fileName, String content) {
        MultipartFile file = FileUtil.createMultipartFile(content.getBytes(StandardCharsets.UTF_8), fileName);
        return uploadHtmlFile(bucket, dir, file);
    }

    // 上传字节数组文件
    public String uploadFile(String bucket, String filePath, byte[] data) {
        if (!containsBucket(bucket))
            createBucket(bucket);
        else if (isObjectExist(bucket, filePath)) {
            bucket = IdUtil.randomUUID() + bucket;
            createBucket(bucket);
        }
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
            minioClient.putObject(PutObjectArgs.builder().bucket(bucket).object(filePath).stream(inputStream, data.length, -1).build());
            return getObjUrl(bucket, filePath, Method.GET);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 流式上传MultipartFile文件
     * @param bucket 桶
     * @param dir 文件目录
     * @param file 文件
     */
    public String uploadFile(String bucket, String dir, MultipartFile file) {
        if (!containsBucket(bucket))
            createBucket(bucket);
        try {
            String filePath = getFilePath(bucket, dir, file);
            minioClient.putObject(PutObjectArgs.builder()
                    .bucket(bucket)
                    .object(filePath)
                    .stream(file.getInputStream(), file.getSize(), -1)
                    .build());
            return getObjUrl(bucket, filePath, Method.GET);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 流式上传MultipartFile文件
     * @param bucket 桶
     * @param dir 文件目录
     * @param file 文件
     */
    public String uploadHtmlFile(String bucket, String dir, MultipartFile file) {
        if (!containsBucket(bucket))
            createBucket(bucket);
        try {
            String filePath = getFilePath(bucket, dir, file);
            minioClient.putObject(PutObjectArgs.builder()
                    .bucket(bucket)
                    .object(filePath)
                    .stream(file.getInputStream(), file.getSize(), -1)
                    .contentType("text/html; charset=utf-8")
                    .build());
            return getObjUrl(bucket, filePath, Method.GET);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 倍增算法获取不重复的文件路径
     * @param bucket
     * @param dir
     * @param file
     * @return
     */
    private String getFilePath(String bucket, String dir, MultipartFile file) {
        String fileName = file.getOriginalFilename();
        int location = 0, jump = 1;
        while (jump > 0) {
            String filePath = dir + separator + (location + jump) + separator + fileName;
            if (isObjectExist(bucket, filePath)) {
                location += jump;
                jump *= 2;
            } else {
                jump /= 2;
            }
        }
        location++;
        return dir + separator +  location + separator + fileName;
    }

    // 创建bucket
    public void createBucket(String bucketName) {
        try {
            if (!minioClient.bucketExists(BucketExistsArgs.builder().bucket(bucketName).build()))
                minioClient.makeBucket(MakeBucketArgs.builder().bucket(bucketName).build());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // 删除桶
    public void removeBucket(String bucketName) {
        try {
            minioClient.removeBucket(RemoveBucketArgs.builder().bucket(bucketName).build());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 判断指定bucket中的文件是否存在
     *
     * @param bucketName 桶名称
     * @param filePath 对象名称
     * @return 文件是否存在
     */
    public boolean isObjectExist(String bucketName, String filePath) {
        try {
            // 使用statObject方法检查对象是否存在
            // 如果对象存在，该方法会返回对象的元数据
            // 如果对象不存在，该方法会抛出异常
            minioClient.statObject(
                    StatObjectArgs.builder()
                            .bucket(bucketName)
                            .object(filePath)
                            .build()
            );
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 从url下载文件并上传到minio，返回新文件url
     * @param fileUrl 文件的http(s)地址
     * @param bucket 目标桶
     * @param dir 目标目录
     * @param fileName 新文件名
     * @return minio文件url
     */
    public String uploadFileFromUrl(String fileUrl, String bucket, String dir, String fileName) {
        try {
            URL url = new URL(fileUrl);
            try (java.io.InputStream in = url.openStream()) {
                byte[] data = in.readAllBytes();
                String filePath = getFilePath(bucket, dir, FileUtil.createMultipartFile(data, fileName));
                return uploadFile(bucket, filePath, data);
            }
        } catch (Exception e) {
            throw new RuntimeException("从url上传到minio失败: " + fileUrl, e);
        }
    }
}