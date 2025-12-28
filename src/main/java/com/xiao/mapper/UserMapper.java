package com.xiao.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.xiao.dao.User;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface UserMapper extends BaseMapper<User> {
    int updateBatch(@Param("list") List<User> list);

    int batchInsert(@Param("list") List<User> list);

    int batchInsertSelectiveUseDefaultForNull(@Param("list") List<User> list);

    int insertOnDuplicateUpdate(User record);

    int insertOnDuplicateUpdateSelective(User record);
}