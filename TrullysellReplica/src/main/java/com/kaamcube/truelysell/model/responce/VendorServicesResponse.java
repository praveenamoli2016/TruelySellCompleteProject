package com.kaamcube.truelysell.model.responce;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.kaamcube.truelysell.model.request.dto.ServiceOfferedDto;
import lombok.Data;

import java.util.List;
import java.util.Set;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VendorServicesResponse {
    private Long id;
    private Long vendorId;
    private String serviceTitle;
    private String serviceAmount;
    private String serviceLocation;
    private String category;
    private String subcategory;
    private Set<ServiceOfferedDto> serviceOffered;
    private String descriptions;
}
