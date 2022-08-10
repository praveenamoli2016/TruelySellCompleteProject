package com.kaamcube.truelysell.model.request.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ServiceOfferedDto {

    @NotBlank(message = "Service offered not null")
    String serviceOffered;
}
