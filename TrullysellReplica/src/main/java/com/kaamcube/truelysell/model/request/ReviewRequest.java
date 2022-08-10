package com.kaamcube.truelysell.model.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ReviewRequest {

    private Long reviewId;

    private Long reviewerId;

    private String comment;

    private Integer rating;

    private Long serviceId;


}
