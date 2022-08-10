package com.kaamcube.truelysell.model.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.kaamcube.truelysell.model.request.dto.ServiceOfferedDto;
import lombok.Data;

import javax.validation.constraints.NotBlank;
import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AddServiceRequest {

    @NotBlank(message = "Service title not null")
    String serviceTitle;

    @NotBlank(message = "Service amount not null")
    String serviceAmount;

    @NotBlank(message = "Service location not null")
    String serviceLocation;

    Long categoryId;
    Long subCategoryId;

    List<ServiceOfferedDto> serviceOfferedDtos;

    @NotBlank(message = "Descriptions not null")
    String descriptions;

}

