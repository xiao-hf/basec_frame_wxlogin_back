package com.xiao.utils;

import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

public class FileUtil {
    
    /**
     * 将字节数组转换为MultipartFile
     * @param bytes 文件字节数组
     * @param fileName 文件名
     * @return MultipartFile对象
     */
    public static MultipartFile createMultipartFile(byte[] bytes, String fileName) {
        return new MultipartFile() {
            @Override
            public String getName() {
                return fileName;
            }

            @Override
            public String getOriginalFilename() {
                return fileName;
            }

            @Override
            public String getContentType() {
                // 根据文件扩展名判断ContentType
                String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
                switch (extension) {
                    case "jpg":
                    case "jpeg":
                        return "image/jpeg";
                    case "png":
                        return "image/png";
                    case "gif":
                        return "image/gif";
                    case "mp3":
                        return "audio/mpeg";
                    case "mp4":
                        return "video/mp4";
                    case "pdf":
                        return "application/pdf";
                    default:
                        return "application/octet-stream";
                }
            }

            @Override
            public boolean isEmpty() {
                return bytes == null || bytes.length == 0;
            }

            @Override
            public long getSize() {
                return bytes.length;
            }

            @Override
            public byte[] getBytes() throws IOException {
                return bytes;
            }

            @Override
            public InputStream getInputStream() throws IOException {
                return new ByteArrayInputStream(bytes);
            }

            @Override
            public void transferTo(File dest) throws IOException, IllegalStateException {
                try (java.io.FileOutputStream fos = new java.io.FileOutputStream(dest)) {
                    fos.write(bytes);
                }
            }
        };
    }
}
