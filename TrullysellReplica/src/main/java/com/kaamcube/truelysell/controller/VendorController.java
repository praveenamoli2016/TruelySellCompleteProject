package com.kaamcube.truelysell.controller;

import com.kaamcube.truelysell.config.TokenProvider;
import com.kaamcube.truelysell.model.request.*;
import com.kaamcube.truelysell.model.responce.Response;
import com.kaamcube.truelysell.service.VendorService;
import com.kaamcube.truelysell.utility.enums.PaymentMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/vendor")
public class VendorController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private TokenProvider jwtTokenUtil;
	@Autowired
	private VendorService vendorService;

	@PostMapping("/registerVendor")
	private Response registerVendor(@Valid @RequestBody RegistrationRequest vendorRequest) {
		return vendorService.registerVendor(vendorRequest);
	}

	@PostMapping("/otpValidation")
	public Response otpValidation(@Valid@RequestBody OtpRequest otpRequest ){
		final Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(otpRequest.getMobileNo(), otpRequest.getOtp()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		final String token = jwtTokenUtil.generateToken(authentication);
		Response response = new Response("SUCCESS", "200", "Vendor logged in Successfully", token);
		return response;
		//return vendorService.otpValidation(otpRequest);
	}

	@PostMapping("/vendorLogin")
	public Response vendorLogin(@Valid@RequestBody LoginRequest loginRequest ){
		return vendorService.vendorLogin(loginRequest);
	}

	@PreAuthorize("hasAnyRole('VENDOR','ADMIN','CUSTOMER')")
	@GetMapping("/getVendor")
	public Response getVendor(@Valid@RequestParam Long vendorId){

		return vendorService.getVendor(vendorId);
	}

	@PreAuthorize("hasAnyRole('VENDOR','ADMIN')")
	@PostMapping("/updateVendor")
	public Response updateVendor(@Valid@RequestBody VendorRequest vendorRequest){
		return vendorService.updateVendor(vendorRequest);
	}

	@PreAuthorize("hasAnyRole('VENDOR','ADMIN','CUSTOMER')")
	@PostMapping("/postService")
	public Response postAvailability(@Valid @ RequestBody AvailabilityRequest availabilityRequest,@RequestParam Long vendorId){
		return vendorService.postAvailability(availabilityRequest,vendorId);
	}

	@PreAuthorize("hasRole('VENDOR')")
	@PostMapping("/addService")
	public Response addService(@Valid @RequestBody AddServiceRequest addServiceRequest,@RequestParam Long vendorId){
		return vendorService.addService(addServiceRequest,vendorId);
	}

	@PreAuthorize("hasAnyRole('VENDOR','ADMIN','CUSTOMER')")
	@GetMapping("/getService")
	public Response getService (@Valid @RequestParam Long vendorId){
		return vendorService.getService(vendorId);
	}

	@PreAuthorize("hasAnyRole('VENDOR','ADMIN','CUSTOMER')")
	@GetMapping("/getServiceDetails")
	public Response getServiceDetails (@Valid @RequestParam Long vendorId,@RequestParam Long vendorServiceId){
		return vendorService.getServiceDetails(vendorId,vendorServiceId);
	}

	@PreAuthorize("hasAnyRole('VENDOR','ADMIN','CUSTOMER')")
	@GetMapping("/getAllServices")
	public Response getAllServices (@Valid@RequestParam(value = "pageNumber",defaultValue = "0",required = false) Integer pageNumber,
									@RequestParam(value = "pageSize",defaultValue = "10",required = false) Integer pageSize,
									@RequestParam(value ="sortBy",defaultValue = "vendorId",required = false) String sortBy,
									@RequestParam(value = "sortDtr",defaultValue = "asc",required = false)String sortDir){
		return vendorService.getAllServices(pageNumber,pageSize,sortBy,sortDir);
	}

	@PreAuthorize("hasAnyRole('VENDOR','ADMIN')")
	@PostMapping("/addSubscriptions")
	public Response addSubscriptions(@Valid@RequestBody SubscriptionRequest subscriptionRequest ){
		return vendorService.addSubscriptions(subscriptionRequest);
	}

	@PreAuthorize("hasAnyRole('VENDOR','ADMIN')")
	@GetMapping("/getSubscriptions")
	public Response getSubscriptions(@Valid@RequestParam Long vendorId){
		return vendorService.getSubscriptions(vendorId);
	}

	//Search

	@PreAuthorize("hasAnyRole('VENDOR','ADMIN','CUSTOMER')")
	@GetMapping("/vendors/search/(keywords)")
	public Response  searchServicesByTitle(
			@Valid@PathVariable("keywords") String keyword
	){
		return vendorService.searchVendorServices(keyword);
	}



}
