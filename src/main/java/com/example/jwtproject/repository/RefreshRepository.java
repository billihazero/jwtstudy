package com.example.jwtproject.repository;

import com.example.jwtproject.entity.RefreshEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {

    Boolean existsByRefresh(String refresh);

    //db의 refresh를 지우기 위한 메서드
    @Transactional
    void deleteByRefresh(String refresh);
}
