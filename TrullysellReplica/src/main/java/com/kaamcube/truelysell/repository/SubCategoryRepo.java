package com.kaamcube.truelysell.repository;

import com.kaamcube.truelysell.model.entity.SubCategory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SubCategoryRepo extends JpaRepository<SubCategory,Long> {
    List<SubCategory> findByCategoryId(Long categoryId);
}
