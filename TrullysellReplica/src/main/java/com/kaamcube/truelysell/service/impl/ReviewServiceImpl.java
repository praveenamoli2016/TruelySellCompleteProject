package com.kaamcube.truelysell.service.impl;

import com.kaamcube.truelysell.model.entity.Review;
import com.kaamcube.truelysell.model.entity.VendorServices;
import com.kaamcube.truelysell.model.request.ReviewRequest;
import com.kaamcube.truelysell.model.responce.Response;
import com.kaamcube.truelysell.repository.ReviewRepo;
import com.kaamcube.truelysell.repository.VendorServiceRepo;
import com.kaamcube.truelysell.service.ReviewService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class ReviewServiceImpl implements ReviewService {

    @Autowired
    private ReviewRepo reviewRepo;

    @Autowired
    private VendorServiceRepo vendorServiceRepo;

    @Override
    public Response sendReview(ReviewRequest reviewRequest) {
        Response response = null;
        try {
            //checking review id is present or not
            if (reviewRequest.getReviewId() != null) {
                //fetching review details from database and update it.
                Optional<Review> reviewOptional = reviewRepo.findById(reviewRequest.getReviewId());
                if (reviewOptional.isPresent()) {
                    Review review = reviewOptional.get();
                    review.setRating(reviewRequest.getRating());
                    review.setComment(reviewRequest.getComment());
                    review.setUpdatedDate(LocalDateTime.now().toString());
                    Review updatedData = reviewRepo.save(review);
                    response = new Response("Success", "200", "Review updated successfully", updatedData);
                } else {
                    throw new Exception("Review not found");
                }
            } else {
                //Adding fresh(new) review in database
                Review review = new Review();
                Optional<VendorServices> vendorServices = vendorServiceRepo.findById(reviewRequest.getServiceId());
                if (!vendorServices.isPresent())
                    throw new Exception("Service not found");
                review.setVendorServices(vendorServices.get());
                review.setReviewerId(reviewRequest.getReviewerId());
                review.setComment(reviewRequest.getComment());
                review.setRating(reviewRequest.getRating());
                review.setCreatedDate(LocalDateTime.now().toString());
                Review savedData = this.reviewRepo.save(review);
                response = new Response("Success", "201", "Review added successfully", savedData);
            }
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response getReview(Long customerId) {
        Response response=null;
        try {
            Optional<Review> optionalReview=reviewRepo.findByReviewerId(customerId);
            if (optionalReview.isPresent()){
                Review review=optionalReview.get();
                response = new Response("Success", "200", "Customer Review fetch successfully", review);

            }
            else {
                response = new Response("Failure", "404", "Review not found ", null);

            }

        }catch (Exception exception){
            response = new Response("Failure", "500", exception.getMessage(), null);

        }
        return response;
    }

    @Override
    public Response deleteReview(Long reviewId) {
        Response response = null;
        try {
            reviewRepo.deleteById(reviewId);
            response = new Response("Success", "200","Record deleted successfully", null);
        } catch (Exception exception){
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response getAllReviews() {
        Response response=null;
        try {
            List<Review> reviewList=reviewRepo.findAll();
            response = new Response("Success", "200", "ReviewList fetched successfully", reviewList);

        }catch (Exception exception){
            response = new Response("Failure", "500", exception.getMessage(), null);

        }
        return response;
    }
}
