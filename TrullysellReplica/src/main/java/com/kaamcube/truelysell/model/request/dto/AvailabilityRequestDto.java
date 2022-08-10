package com.kaamcube.truelysell.model.request.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AvailabilityRequestDto {
    @NotBlank(message = "Day not null")
    String day;
    @NotBlank(message = "FromDate not null")
    String fromDate;
    @NotBlank(message = "ToDate not null")
    String toDate;
}
