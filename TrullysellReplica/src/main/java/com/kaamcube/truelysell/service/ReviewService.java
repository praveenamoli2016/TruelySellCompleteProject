package com.kaamcube.truelysell.service;

import com.kaamcube.truelysell.model.entity.Review;
import com.kaamcube.truelysell.model.request.ReviewRequest;
import com.kaamcube.truelysell.model.responce.Response;

public interface ReviewService {

    Response sendReview(ReviewRequest reviewRequest);

    Response getReview(Long customerId);

    Response deleteReview(Long reviewId);

    Response getAllReviews();
}
