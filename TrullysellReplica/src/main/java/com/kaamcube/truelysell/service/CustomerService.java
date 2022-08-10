package com.kaamcube.truelysell.service;

import com.kaamcube.truelysell.model.request.*;
import com.kaamcube.truelysell.model.responce.Response;

public interface CustomerService {
    Response registerCustomer(RegistrationRequest customerRequest);

    Response otpValidation(OtpRequest otpRequest);

    Response customerLogin(LoginRequest loginRequest);

    Response getCustomer(Long customerId);

    Response updateCustomer(CustomerRequest customerRequest);

    Response bookService(BookServiceRequest bookServiceRequest);

    Response getCustomerBooking(Long customerId);

    Response getWalletAmount(Long customerId);

    Response addWalletAmount(AddWalletAmountRequest addWalletAmountRequest);

    Response getWalletTransaction(Long customerId);
}
