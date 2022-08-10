package com.kaamcube.truelysell.service;

import com.kaamcube.truelysell.model.request.*;
import com.kaamcube.truelysell.model.responce.Response;

public interface VendorService {

	Response registerVendor(RegistrationRequest vendorRequest);

	Response otpValidation(OtpRequest otpRequest);

	Response vendorLogin(LoginRequest loginRequest);


    Response getVendor(Long vendorId);

	Response updateVendor(VendorRequest vendorRequest);
	Response postAvailability(AvailabilityRequest availabilityRequest, Long vendorId);

	Response addService(AddServiceRequest addServiceRequest, Long vendorId);

	Response getService(Long vendorId);

	Response getServiceDetails(Long vendorId, Long vendorServiceDetails);

	Response getAllServices(Integer pageNumber, Integer pageSize,String sortBy,String sortDir);

	Response addSubscriptions(SubscriptionRequest subscriptionRequest);

	Response getSubscriptions(Long vendorId);

	Response searchVendorServices(String keyword);

}
