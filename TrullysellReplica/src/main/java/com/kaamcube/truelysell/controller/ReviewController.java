package com.kaamcube.truelysell.controller;

import com.kaamcube.truelysell.model.entity.Review;
import com.kaamcube.truelysell.model.request.ReviewRequest;
import com.kaamcube.truelysell.model.responce.Response;
import com.kaamcube.truelysell.service.ReviewService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/review")
public class ReviewController {
    @Autowired
    ReviewService reviewService;

    @PreAuthorize("hasAnyRole('ADMIN','CUSTOMER')")
    @PostMapping("/sendReview")
    public Response sendReview(@RequestBody ReviewRequest reviewRequest){
        return reviewService.sendReview(reviewRequest);
    }

    @PreAuthorize("hasAnyRole('ADMIN','CUSTOMER')")
    @GetMapping ("/getReview/{customerId}")
    public Response getReview(@Valid @PathVariable Long customerId){
        return reviewService.getReview(customerId);
    }

    @PreAuthorize("hasAnyRole('ADMIN','CUSTOMER')")
    @GetMapping ("/getAllReviews")
    public Response getAllReviews(){
        return reviewService.getAllReviews();
    }


    @PreAuthorize("hasAnyRole('ADMIN','CUSTOMER')")
    @DeleteMapping("/delete/{id}")
    public Response deleteReview(@PathVariable Long id){
        return reviewService.deleteReview(id);
    }
}
