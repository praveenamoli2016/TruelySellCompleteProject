package com.kaamcube.truelysell.repository;

import com.kaamcube.truelysell.model.entity.Review;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ReviewRepo extends JpaRepository<Review,Long> {

    Optional<Review> findByReviewerId(Long customerId);
}
