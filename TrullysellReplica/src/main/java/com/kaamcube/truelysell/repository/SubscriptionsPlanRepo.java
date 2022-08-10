package com.kaamcube.truelysell.repository;

import com.kaamcube.truelysell.model.entity.SubscriptionsPlan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SubscriptionsPlanRepo extends JpaRepository<SubscriptionsPlan,Long> {

}
