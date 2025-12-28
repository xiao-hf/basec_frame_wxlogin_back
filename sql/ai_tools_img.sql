/*
 Navicat Premium Dump SQL

 Source Server         : localhost
 Source Server Type    : MySQL
 Source Server Version : 80041 (8.0.41)
 Source Host           : localhost:3306
 Source Schema         : ai_tools_img

 Target Server Type    : MySQL
 Target Server Version : 80041 (8.0.41)
 File Encoding         : 65001

 Date: 29/12/2025 05:25:08
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for app_img
-- ----------------------------
DROP TABLE IF EXISTS `app_img`;
CREATE TABLE `app_img`  (
  `id` bigint NOT NULL COMMENT '主键',
  `app_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '小程序id',
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '小程序名字',
  `create_time` datetime NULL DEFAULT NULL COMMENT '创建时间',
  `update_time` datetime NULL DEFAULT NULL COMMENT '修改时间',
  `wx_img` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '企业微信图片',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of app_img
-- ----------------------------

-- ----------------------------
-- Table structure for permission
-- ----------------------------
DROP TABLE IF EXISTS `permission`;
CREATE TABLE `permission`  (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `permission_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '权限名称',
  `content` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '权限内容',
  `type` int NULL DEFAULT NULL COMMENT '权限类别，url-1，other-2',
  `remark` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '备注',
  `create_date` datetime NULL DEFAULT NULL COMMENT '插入时间',
  `update_date` datetime NULL DEFAULT NULL COMMENT '更新时间',
  `create_user_id` bigint NULL DEFAULT NULL COMMENT '创建人',
  `update_user_id` bigint NULL DEFAULT NULL COMMENT '修改人',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 11 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin COMMENT = '权限信息表' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of permission
-- ----------------------------

-- ----------------------------
-- Table structure for role
-- ----------------------------
DROP TABLE IF EXISTS `role`;
CREATE TABLE `role`  (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `role_code` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL COMMENT '角色编码',
  `role_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL COMMENT '角色名称',
  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `idx_role_code`(`role_code` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 3 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of role
-- ----------------------------
INSERT INTO `role` VALUES (1, 'ADMIN', '管理员', '2025-04-11 16:01:50', '2025-04-11 16:01:50');
INSERT INTO `role` VALUES (2, 'USER', '用户', '2025-04-11 16:02:03', '2025-04-11 16:02:03');

-- ----------------------------
-- Table structure for role_permission
-- ----------------------------
DROP TABLE IF EXISTS `role_permission`;
CREATE TABLE `role_permission`  (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `role_id` bigint NOT NULL COMMENT '角色ID',
  `permission_id` bigint NOT NULL COMMENT '权限ID',
  `create_date` datetime NULL DEFAULT NULL COMMENT '插入时间',
  `update_date` datetime NULL DEFAULT NULL COMMENT '更新时间',
  `create_user_id` bigint NULL DEFAULT NULL COMMENT '创建人',
  `update_user_id` bigint NULL DEFAULT NULL COMMENT '修改人',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `idx_role_permission`(`role_id` ASC, `permission_id` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin COMMENT = '角色权限关系表' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of role_permission
-- ----------------------------

-- ----------------------------
-- Table structure for sys_login_log
-- ----------------------------
DROP TABLE IF EXISTS `sys_login_log`;
CREATE TABLE `sys_login_log`  (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '日志ID',
  `user_id` bigint NULL DEFAULT NULL COMMENT '用户ID',
  `username` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '用户名',
  `ip` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '登录IP',
  `browser` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '浏览器类型',
  `os` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '操作系统',
  `device_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '设备类型(PC/Mobile)',
  `status` tinyint NULL DEFAULT NULL COMMENT '登录状态（0失败 1成功）',
  `msg` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '提示消息',
  `login_time` datetime NULL DEFAULT NULL COMMENT '登录时间',
  `login_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT 'PASSWORD' COMMENT '登录类型（PASSWORD-密码登录，CODE-验证码登录，SSO-单点登录）',
  `user_agent` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '用户代理信息',
  `login_module` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '登录模块(前台/后台)',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_user_id`(`user_id` ASC) USING BTREE,
  INDEX `idx_login_time`(`login_time` ASC) USING BTREE,
  INDEX `idx_status`(`status` ASC) USING BTREE,
  INDEX `idx_username`(`username` ASC) USING BTREE,
  INDEX `idx_ip`(`ip` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 6 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '系统登录日志' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of sys_login_log
-- ----------------------------
INSERT INTO `sys_login_log` VALUES (1, NULL, NULL, '127.0.0.1', 'Chrome', 'Windows', 'PC', 1, '登录成功', '2025-04-15 14:59:10', 'CODE', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36', 'PORTAL', '2025-04-15 14:59:10');
INSERT INTO `sys_login_log` VALUES (2, 1, '1', '127.0.0.1', 'Chrome', 'Windows', 'PC', 1, '登录成功', '2025-04-15 15:03:46', 'CODE', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36', 'PORTAL', '2025-04-15 15:03:46');
INSERT INTO `sys_login_log` VALUES (3, 1, '1', '127.0.0.1', 'Chrome', 'Windows', 'PC', 1, '登录成功', '2025-04-15 15:06:45', 'LOGOUT', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36', 'PORTAL', '2025-04-15 15:06:45');
INSERT INTO `sys_login_log` VALUES (4, 1, '1', '127.0.0.1', 'Chrome', 'Windows', 'PC', 1, '登录成功', '2025-04-15 15:13:05', 'CODE', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36', 'PORTAL', '2025-04-15 15:13:06');
INSERT INTO `sys_login_log` VALUES (5, 1, '1', '127.0.0.1', 'Chrome', 'Windows', 'PC', 1, '登出成功', '2025-04-15 15:13:15', 'LOGOUT', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36', 'PORTAL', '2025-04-15 15:13:15');

-- ----------------------------
-- Table structure for sys_operation_log
-- ----------------------------
DROP TABLE IF EXISTS `sys_operation_log`;
CREATE TABLE `sys_operation_log`  (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '日志主键',
  `module` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '模块名称',
  `operation_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '操作类型',
  `description` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '操作描述',
  `method` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '请求方法',
  `request_url` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '请求URL',
  `request_method` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '请求方式',
  `request_params` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL COMMENT '请求参数',
  `response_result` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL COMMENT '返回结果',
  `status` tinyint NULL DEFAULT NULL COMMENT '操作状态（0失败 1成功）',
  `error_msg` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL COMMENT '错误消息',
  `user_id` bigint NULL DEFAULT NULL COMMENT '操作用户ID',
  `username` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '操作用户名',
  `ip` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '操作用户IP',
  `browser` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '浏览器类型',
  `os` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '操作系统',
  `time` bigint NULL DEFAULT NULL COMMENT '执行时长(毫秒)',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_user_id`(`user_id` ASC) USING BTREE,
  INDEX `idx_status`(`status` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 25 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci COMMENT = '系统操作日志' ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of sys_operation_log
-- ----------------------------
INSERT INTO `sys_operation_log` VALUES (7, '测试', 'OTHER', '', 'com.xiao.controller.UserController.admin()', '/user/admin', 'GET', NULL, '{\"success\":true,\"code\":\"200\",\"message\":\"\",\"data\":\"ADMIN认证成功!\",\"timestamp\":1744700185803}', 1, NULL, 1, '1', '127.0.0.1', 'Chrome', 'Windows', 2, NULL);
INSERT INTO `sys_operation_log` VALUES (8, '测试', 'OTHER', '', 'com.xiao.controller.UserController.admin()', '/user/admin', 'GET', NULL, '{\"success\":true,\"code\":\"200\",\"message\":\"\",\"data\":\"ADMIN认证成功!\",\"timestamp\":1744700202944}', 1, NULL, 1, '1', '127.0.0.1', 'Chrome', 'Windows', 0, NULL);
INSERT INTO `sys_operation_log` VALUES (9, '测试', 'OTHER', '', 'com.xiao.controller.UserController.admin()', '/user/admin', 'GET', NULL, '{\"success\":true,\"code\":\"200\",\"message\":\"\",\"data\":\"ADMIN认证成功!\",\"timestamp\":1744700203529}', 1, NULL, 1, '1', '127.0.0.1', 'Chrome', 'Windows', 0, NULL);
INSERT INTO `sys_operation_log` VALUES (10, '测试', 'OTHER', '', 'com.xiao.controller.UserController.admin()', '/user/admin', 'GET', NULL, '{\"success\":true,\"code\":\"200\",\"message\":\"\",\"data\":\"ADMIN认证成功!\",\"timestamp\":1744700235383}', 1, NULL, 1, '1', '127.0.0.1', 'Chrome', 'Windows', 0, NULL);
INSERT INTO `sys_operation_log` VALUES (11, '测试', 'OTHER', '', 'com.xiao.controller.UserController.admin()', '/user/admin', 'GET', NULL, '{\"success\":true,\"code\":\"200\",\"message\":\"\",\"data\":\"ADMIN认证成功!\",\"timestamp\":1744700235705}', 1, NULL, 1, '1', '127.0.0.1', 'Chrome', 'Windows', 0, NULL);
INSERT INTO `sys_operation_log` VALUES (12, '登录', 'OTHER', '', 'com.xiao.controller.UserController.login()', '/user/login', 'POST', '{\"req\":{\"phone\":\"15286610576\",\"code\":\"114514\",\"type\":\"2\"}}', NULL, 1, NULL, NULL, NULL, '127.0.0.1', 'Chrome', 'Windows', 794, '2025-12-28 12:44:23');
INSERT INTO `sys_operation_log` VALUES (13, '登录', 'OTHER', '', 'com.xiao.controller.UserController.login()', '/user/login', 'POST', '{\"req\":{\"phone\":\"15286610576\",\"code\":\"114514\",\"type\":\"2\"}}', NULL, 1, NULL, NULL, NULL, '127.0.0.1', 'Chrome', 'Windows', 17, '2025-12-28 12:44:39');
INSERT INTO `sys_operation_log` VALUES (14, '登录', 'OTHER', '', 'com.xiao.controller.UserController.login()', '/user/login', 'POST', '{\"req\":{\"phone\":\"15286610576\",\"code\":\"114514\",\"type\":\"2\"}}', NULL, 1, NULL, NULL, NULL, '127.0.0.1', 'Chrome', 'Windows', 7, '2025-12-28 12:44:41');
INSERT INTO `sys_operation_log` VALUES (15, '登录', 'OTHER', '', 'com.xiao.controller.UserController.login()', '/user/login', 'POST', '{\"req\":{\"phone\":\"15286610576\",\"code\":\"324545\",\"type\":\"2\"}}', NULL, 1, NULL, 1, '1', '127.0.0.1', 'Chrome', 'Windows', 219, '2025-12-28 12:45:11');
INSERT INTO `sys_operation_log` VALUES (16, '注册', 'OTHER', '', 'com.xiao.controller.UserController.register()', '/user/register', 'POST', '{\"req\":{\"username\":\"aaa\",\"phone\":\"19352311776\",\"password\":\"114514\",\"code\":\"216852\",\"realName\":\"\",\"policeId\":null,\"idCard\":\"\",\"gender\":0,\"email\":\"\",\"avatar\":\"\",\"position\":\"\",\"unitId\":0}}', NULL, 1, NULL, NULL, NULL, '127.0.0.1', 'Chrome', 'Windows', 574, '2025-12-28 13:22:53');
INSERT INTO `sys_operation_log` VALUES (17, '注册', 'OTHER', '', 'com.xiao.controller.UserController.register()', '/user/register', 'POST', '{\"req\":{\"username\":\"aaa\",\"phone\":\"19352311776\",\"password\":\"114514\",\"code\":\"613254\",\"realName\":\"\",\"policeId\":null,\"idCard\":\"\",\"gender\":0,\"email\":\"\",\"avatar\":\"\",\"position\":\"\",\"unitId\":0}}', NULL, 0, '\r\n### Error updating database.  Cause: org.apache.ibatis.reflection.ReflectionException: There is no getter for property named \'policeId\' in \'class com.xiao.dao.User\'\r\n### The error may exist in file [D:\\A_接单\\mybatis-plus\\basic_frame_back\\target\\classes\\mapper\\UserMapper.xml]\r\n### The error may involve com.xiao.mapper.UserMapper.insert-Inline\r\n### The error occurred while setting parameters\r\n### SQL: insert into `user` (username, `password`, police_id,        real_name, unit_id, `position`,        id_card, gender, phone,        email, avatar, `enable`,        create_time, update_time, last_login_time,        is_deleted, token)     values (?, ?, ?,        ?, ?, ?,        ?, ?, ?,        ?, ?, ?,        ?, ?, ?,        ?, ?)\r\n### Cause: org.apache.ibatis.reflection.ReflectionException: There is no getter for property named \'policeId\' in \'class com.xiao.dao.User\'', NULL, NULL, '127.0.0.1', 'Chrome', 'Windows', 123, '2025-12-28 13:23:18');
INSERT INTO `sys_operation_log` VALUES (18, '注册', 'OTHER', '', 'com.xiao.controller.UserController.register()', '/user/register', 'POST', '{\"req\":{\"username\":\"aaa\",\"phone\":\"19352311776\",\"password\":\"114514\",\"code\":\"118208\",\"realName\":\"\",\"idCard\":\"\",\"gender\":0,\"email\":\"\",\"avatar\":\"\",\"position\":\"\",\"unitId\":0}}', NULL, 0, '\r\n### Error updating database.  Cause: org.apache.ibatis.reflection.ReflectionException: There is no getter for property named \'policeId\' in \'class com.xiao.dao.User\'\r\n### The error may exist in file [D:\\A_接单\\mybatis-plus\\basic_frame_back\\target\\classes\\mapper\\UserMapper.xml]\r\n### The error may involve com.xiao.mapper.UserMapper.insert-Inline\r\n### The error occurred while setting parameters\r\n### SQL: insert into `user` (username, `password`, police_id,        real_name, unit_id, `position`,        id_card, gender, phone,        email, avatar, `enable`,        create_time, update_time, last_login_time,        is_deleted, token)     values (?, ?, ?,        ?, ?, ?,        ?, ?, ?,        ?, ?, ?,        ?, ?, ?,        ?, ?)\r\n### Cause: org.apache.ibatis.reflection.ReflectionException: There is no getter for property named \'policeId\' in \'class com.xiao.dao.User\'', NULL, NULL, '127.0.0.1', 'Chrome', 'Windows', 467, '2025-12-28 13:31:23');
INSERT INTO `sys_operation_log` VALUES (19, '注册', 'OTHER', '', 'com.xiao.controller.UserController.register()', '/user/register', 'POST', '{\"req\":{\"username\":\"aaa\",\"phone\":\"19352311776\",\"password\":\"114514\",\"code\":\"686570\",\"realName\":\"\",\"idCard\":\"\",\"gender\":0,\"email\":\"\",\"avatar\":\"\",\"position\":\"\",\"unitId\":0}}', NULL, 1, NULL, NULL, NULL, '127.0.0.1', 'Chrome', 'Windows', 532, '2025-12-28 13:36:10');
INSERT INTO `sys_operation_log` VALUES (20, '登录', 'OTHER', '', 'com.xiao.controller.UserController.login()', '/user/login', 'POST', '{\"req\":{\"phone\":\"19352311776\",\"code\":\"114514\",\"type\":\"2\"}}', NULL, 1, NULL, NULL, NULL, '127.0.0.1', 'Chrome', 'Windows', 11, '2025-12-28 13:36:22');
INSERT INTO `sys_operation_log` VALUES (21, '登录', 'OTHER', '', 'com.xiao.controller.UserController.login()', '/user/login', 'POST', '{\"req\":{\"phone\":\"19352311776\",\"code\":\"114514\",\"type\":\"1\"}}', NULL, 1, NULL, NULL, NULL, '127.0.0.1', 'Chrome', 'Windows', 105, '2025-12-28 13:36:27');
INSERT INTO `sys_operation_log` VALUES (22, '注册', 'OTHER', '', 'com.xiao.controller.UserController.register()', '/user/register', 'POST', '{\"req\":{\"username\":\"aaa\",\"phone\":\"19352311776\",\"password\":\"114514\",\"code\":\"202528\",\"realName\":\"\",\"idCard\":\"\",\"gender\":0,\"email\":\"\",\"avatar\":\"\",\"position\":\"\",\"unitId\":0}}', NULL, 1, NULL, NULL, NULL, '127.0.0.1', 'Chrome', 'Windows', 397, '2025-12-28 13:44:05');
INSERT INTO `sys_operation_log` VALUES (23, '登录', 'OTHER', '', 'com.xiao.controller.UserController.login()', '/user/login', 'POST', '{\"req\":{\"phone\":\"19352311776\",\"code\":\"114514\",\"type\":\"1\"}}', NULL, 1, NULL, 4, 'aaa', '127.0.0.1', 'Chrome', 'Windows', 178, '2025-12-28 13:44:10');
INSERT INTO `sys_operation_log` VALUES (24, '登录', 'OTHER', '', 'com.xiao.controller.UserController.login()', '/user/login', 'POST', '{\"req\":{\"openId\":\"sfsdafdsfdsdf\"}}', NULL, 1, NULL, 5, 'wx_sfsdafdsfdsdf', '127.0.0.1', 'Chrome', 'Windows', 1038, '2025-12-29 05:22:44');

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user`  (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `username` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL COMMENT '登录用户名',
  `password` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL COMMENT '密码',
  `real_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL COMMENT '真实姓名',
  `unit_id` bigint NOT NULL COMMENT '所属部门/单位ID',
  `position` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '职位',
  `id_card` varchar(18) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '身份证号',
  `gender` tinyint NULL DEFAULT NULL COMMENT '性别：0-女，1-男',
  `phone` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '联系电话',
  `email` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '电子邮箱',
  `avatar` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '头像URL',
  `enable` bit(1) NOT NULL DEFAULT b'1' COMMENT '是否启用',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `update_time` datetime NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  `last_login_time` datetime NULL DEFAULT NULL COMMENT '最后登录时间',
  `is_deleted` bit(1) NOT NULL COMMENT '是否删除',
  `token` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '登陆成功token',
  `wx_open_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL COMMENT '微信登录的openId',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `username`(`username` ASC) USING BTREE,
  UNIQUE INDEX `idx_username`(`username` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 6 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of user
-- ----------------------------
INSERT INTO `user` VALUES (1, '1', '1', '1', 1, '1', '1', 1, '15286610576', '1', '1', b'1', '1970-01-03 00:00:00', '2025-04-11 14:44:41', '2025-12-28 12:45:11', b'0', '259a8f15-5cc6-4cf8-90e8-e93b404d6366', '');
INSERT INTO `user` VALUES (2, '323', '1', '1', 1, '1', '1', 1, '15286610576', '1', '1', b'0', '1970-01-03 00:00:00', '2025-04-11 16:13:25', '1970-01-02 00:00:00', b'1', NULL, '');
INSERT INTO `user` VALUES (4, 'aaa', '114514', '', 0, '', '', 0, '19352311776', '', '', b'1', '2025-12-28 13:44:04', '2025-12-28 13:44:04', '2025-12-28 13:44:10', b'0', '2e75f35d-9170-4956-81f5-1edf5766faea', '');
INSERT INTO `user` VALUES (5, 'wx_sfsdafdsfdsdf', '9cdacf83-a22f-4245-8bc1-9faa84b2e107', '', 0, NULL, NULL, NULL, NULL, NULL, NULL, b'1', '2025-12-29 05:22:43', '2025-12-29 05:22:43', '2025-12-29 05:22:43', b'0', 'b1676e18-2eff-445d-a941-e3a915115a51', 'sfsdafdsfdsdf');

-- ----------------------------
-- Table structure for user_role
-- ----------------------------
DROP TABLE IF EXISTS `user_role`;
CREATE TABLE `user_role`  (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL COMMENT '用户ID',
  `role_id` bigint NOT NULL COMMENT '角色ID',
  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `create_by` bigint NULL DEFAULT NULL COMMENT '创建人ID',
  PRIMARY KEY (`id`, `user_id`) USING BTREE,
  UNIQUE INDEX `idx_user_role`(`user_id` ASC, `role_id` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of user_role
-- ----------------------------
INSERT INTO `user_role` VALUES (1, 1, 1, '2025-04-11 16:18:11', NULL);
INSERT INTO `user_role` VALUES (2, 4, 2, '2025-12-28 13:44:04', NULL);
INSERT INTO `user_role` VALUES (3, 5, 2, '2025-12-29 05:22:43', NULL);

SET FOREIGN_KEY_CHECKS = 1;
