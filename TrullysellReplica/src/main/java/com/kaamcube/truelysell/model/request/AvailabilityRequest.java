package com.kaamcube.truelysell.model.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.kaamcube.truelysell.model.request.dto.AvailabilityRequestDto;
import lombok.Data;

import javax.validation.constraints.NotBlank;
import java.util.List;
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AvailabilityRequest {
    @NotBlank(message = "AvailabilityRequest is mandatory")
    List<AvailabilityRequestDto> availabilityRequestDtos;
}
