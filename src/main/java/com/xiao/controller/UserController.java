package com.xiao.controller;

import com.xiao.common.AjaxResult;
import com.xiao.common.annotation.Log;
import com.xiao.common.dto.UserDto;
import com.xiao.http.req.ReqWxLogin;
import com.xiao.service.UserService;
import com.xiao.utils.SecurityUtil;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.annotation.Resource;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @Resource
    UserService userService;

    @GetMapping("/getLoginUser")
    public AjaxResult<UserDto> getLoginUser() {
        return AjaxResult.success(SecurityUtil.getUser());
    }

    @Operation(summary = "生成验证码")
    @GetMapping("/getCaptcha/{phone}")
    public AjaxResult<String> geneCode(@PathVariable String phone) {
        return userService.geneCode(phone);
    }

    @Operation(summary = "登录")
    @PostMapping("/login")
    @Log(module = "登录")
    public AjaxResult<String> login(@RequestBody @Valid ReqWxLogin req) {
        return userService.login(req);
    }

    @Operation(summary = "退出")
    @PostMapping("/logout")
    @Log(module = "退出")
    public AjaxResult<String> logout() {
        return userService.logout();
    }
}
