package com.xiao.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.xiao.dao.AppImg;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface AppImgMapper extends BaseMapper<AppImg> {
    int updateBatch(@Param("list") List<AppImg> list);

    int batchInsert(@Param("list") List<AppImg> list);

    int batchInsertSelectiveUseDefaultForNull(@Param("list") List<AppImg> list);

    int insertOnDuplicateUpdate(AppImg record);

    int insertOnDuplicateUpdateSelective(AppImg record);
}