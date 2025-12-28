package com.xiao.service;

import com.xiao.common.AjaxResult;
import com.xiao.http.req.ReqWxLogin;

public interface UserService {

    AjaxResult<String> geneCode(String phone);

    AjaxResult<String> login(ReqWxLogin req);

    AjaxResult<String> logout();
}
