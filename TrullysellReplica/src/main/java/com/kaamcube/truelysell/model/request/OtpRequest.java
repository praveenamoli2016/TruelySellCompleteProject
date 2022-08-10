package com.kaamcube.truelysell.model.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OtpRequest {
        @NotBlank(message = "Otp is mandatory")
        private String otp;
        @NotBlank(message = "Mobile number is mandatory")
        private String mobileNo;
    }

