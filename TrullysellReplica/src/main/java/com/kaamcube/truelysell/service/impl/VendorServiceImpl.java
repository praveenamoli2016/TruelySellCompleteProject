package com.kaamcube.truelysell.service.impl;

import com.kaamcube.truelysell.model.entity.*;
import com.kaamcube.truelysell.model.request.*;
import com.kaamcube.truelysell.model.request.dto.ServiceOfferedDto;
import com.kaamcube.truelysell.model.responce.Response;
import com.kaamcube.truelysell.model.responce.VendorRegisterResponse;
import com.kaamcube.truelysell.model.responce.VendorServicesResponse;
import com.kaamcube.truelysell.repository.*;
import com.kaamcube.truelysell.service.RoleService;
import com.kaamcube.truelysell.service.VendorService;
import com.kaamcube.truelysell.utility.TruelySellUtility;
import com.kaamcube.truelysell.utility.enums.Status;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;

@Service
public class VendorServiceImpl implements VendorService {
    @Autowired
    private VendorRepo vendorRepo;

    @Autowired
    private VendorAvailabilityRepo vendorAvailabilityRepo;

    @Autowired
    private SubscriptionsPlanRepo subscriptionsPlanRepo;

    @Autowired
    private SubscriptionRepo subscriptionRepo;

    @Autowired
    private VendorServiceRepo vendorServiceRepo;

    @Autowired
    private ServiceOfferRepo serviceOfferRepo;

    @Autowired
    private RoleService roleService;

    @Autowired
    BCryptPasswordEncoder encoder;

    @Override
    public Response registerVendor(RegistrationRequest vendorRequest) {
        Response response = null;
        try {
            //preparing vendor details
            Vendor vendor = new Vendor();
            vendor.setName(vendorRequest.getName());
            vendor.setMobileNumber(vendorRequest.getMobileNo());
            vendor.setEmail(vendorRequest.getEmail());
            vendor.setPassword(vendorRequest.getPassword());
            vendor.setTermsAndCondition(vendorRequest.getTermsAndCondition());
            vendor.setCreatedDate(LocalDateTime.now().toString());

            //Assigning role to vendor
            Role role = roleService.findByName("VENDOR");
            Role role2 = roleService.findByName("ADMIN");
            Set<Role> roleSet = new HashSet<>();
            roleSet.add(role);
            roleSet.add(role2);
            vendor.setRoleSet(roleSet);

            //saving vendor details on database
            Vendor vendorData = vendorRepo.save(vendor);

            //preparing response
            VendorRegisterResponse vendorRegisterResponse = new VendorRegisterResponse(vendorData.getId(),vendorData.getName(), vendorData.getEmail(), vendorData.getPassword(), vendorData.getMobileNumber(), vendorData.getTermsAndCondition(), vendorData.getCreatedDate(), vendorData.getUpdatedDate());

            //preparing response for sending back
            response = new Response("Success", "201", "Vendor added successfully", vendorRegisterResponse);

            //sending otp to verify mobile no and save otp in data for future validation
            String otp = TruelySellUtility.sendOTP(vendorData.getMobileNumber());
            vendorData.setOtp(encoder.encode(otp));
            //updating otp in Database
            vendorRepo.save(vendorData);

        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response otpValidation(OtpRequest otpRequest) {
        Response response = null;
        try {
            Optional<Vendor> vendorOptional = vendorRepo.findByMobileNumber(otpRequest.getMobileNo());
            if (vendorOptional.isPresent()) {
                Vendor vendor = vendorOptional.get();
                if (vendor.getOtp().equals(otpRequest.getOtp())) {
                    response = new Response("Success", "200", "otp verified", null);
                } else {
                    response = new Response("Failure", "401", "otp mismatched", null);
                }
            } else {
                response = new Response("Failure", "404", "Vendor not found with given mobile number", null);
            }
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response vendorLogin(LoginRequest loginRequest) {
        Response response = null;
        try {
            Optional<Vendor> vendorOptional = vendorRepo.findByMobileNumber(loginRequest.getMobileNo());
            if (vendorOptional.isPresent()) {
                Vendor vendor = vendorOptional.get();
                String otp = TruelySellUtility.sendOTP(vendor.getMobileNumber());
                vendor.setOtp(otp);
                //updating otp in Database
                vendorRepo.save(vendor);
                response = new Response("Success", "200", "otp sent successfully", null);
            } else {
                response = new Response("Failure", "404", "Vendor not found with given mobile number", null);
            }
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response getVendor(Long vendorId) {
        Response response = null;
        try {
            Optional<Vendor> vendorOptional = vendorRepo.findById(vendorId);
            if (vendorOptional.isPresent()) {
                Vendor vendor = vendorOptional.get();
                response = new Response("Success", "200", "vendor fetched successfully", vendor);
            } else {
                response = new Response("Failure", "404", "Vendor not found ", null);
            }
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response updateVendor(VendorRequest vendorRequest) {
        Response response = null;
        try {
            Optional<Vendor> vendorOptional = vendorRepo.findById(vendorRequest.getId());
            if (vendorOptional.isPresent()) {
                Vendor vendor = vendorOptional.get();
                //preparing vendor details
                vendor.setName(vendorRequest.getName());
                vendor.setMobileNumber(vendorRequest.getMobileNumber());
                vendor.setEmail(vendorRequest.getEmail());
                vendor.setPassword(vendorRequest.getPassword());
                vendor.setTermsAndCondition(vendorRequest.getTermsAndCondition());
                vendor.setAddress(vendorRequest.getAddress());
                vendor.setCountry(vendorRequest.getCountry());
                vendor.setCountryCode(vendorRequest.getCountryCode());
                vendor.setDateOfBirth(vendorRequest.getDateOfBirth());
                vendor.setState(vendorRequest.getState());
                vendor.setCity(vendorRequest.getCity());
                vendor.setAccountHolderName(vendorRequest.getAccountHolderName());
                vendor.setPanNo(vendorRequest.getPanNo());
                vendor.setPostalCode(vendorRequest.getPostalCode());
                vendor.setBankAddress(vendorRequest.getBankAddress());
                vendor.setBankName(vendorRequest.getBankName());
                vendor.setAcountEmailId(vendorRequest.getAccountEmailId());
                vendor.setIFSCCode(vendorRequest.getIFSCCode());
                vendor.setSortCode(vendorRequest.getSortCode());
                vendor.setPaymentPurchage(vendorRequest.getPaymentPurchase());
                vendor.setRoutingNo(vendorRequest.getRoutingNo());
                //saving vendor details on database
                Vendor updatedVendorData = vendorRepo.save(vendor);
                response = new Response("Success", "200", "Vendor updated ", updatedVendorData);
            } else {
                response = new Response("Failure", "404", "Vendor not found ", null);
            }
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response postAvailability(AvailabilityRequest availabilityRequest, Long vendorId) {
        Response response = null;
        try {

            List<VendorAvailability> vendorAvailabilityList = new ArrayList<>();
            if (availabilityRequest.getAvailabilityRequestDtos().get(0).getDay().equalsIgnoreCase("All")) {
                VendorAvailability vendorAvailability = new VendorAvailability();
                vendorAvailability.setVendorId(vendorId);
                vendorAvailability.setDay(availabilityRequest.getAvailabilityRequestDtos().get(0).getDay());
                vendorAvailability.setFromDate(availabilityRequest.getAvailabilityRequestDtos().get(0).getFromDate());
                vendorAvailability.setToDate(availabilityRequest.getAvailabilityRequestDtos().get(0).getToDate());
                vendorAvailabilityList.add(vendorAvailability);
            } else {
                for (int i = 0; i < 7; i++) {
                    VendorAvailability vendorAvailability = new VendorAvailability();
                    vendorAvailability.setVendorId(vendorId);
                    vendorAvailability.setDay(availabilityRequest.getAvailabilityRequestDtos().get(0).getDay());
                    vendorAvailability.setFromDate(availabilityRequest.getAvailabilityRequestDtos().get(0).getFromDate());
                    vendorAvailability.setToDate(availabilityRequest.getAvailabilityRequestDtos().get(0).getToDate());
                    vendorAvailabilityList.add(vendorAvailability);
                }
            }
            List<VendorAvailability> vendorAvailabilities = vendorAvailabilityRepo.saveAll(vendorAvailabilityList);
            response = new Response("Success", "201", "Availibility added succesfully", vendorAvailabilities);
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Autowired
    private CategoryRepo categoryRepo;

    @Autowired
    private SubCategoryRepo subCategoryRepo;

    @Override
    public Response addService(AddServiceRequest addServiceRequest, Long vendorId) {
        Response response = null;
        try {
            VendorServices vendorServices = new VendorServices();
            Optional<Category> categoryOptional = categoryRepo.findById(addServiceRequest.getCategoryId());
            if (categoryOptional.isPresent())
                vendorServices.setCategory(categoryOptional.get());
            else
                throw new Exception("Category not found");

            Optional<SubCategory> subCategoryOptional = subCategoryRepo.findById(addServiceRequest.getSubCategoryId());
            if (subCategoryOptional.isPresent())
                vendorServices.setSubCategory(subCategoryOptional.get());
            else
                throw new Exception("SubCategory not found");

            Optional<Vendor> vendorOptional = vendorRepo.findById(vendorId);
            if (vendorOptional.isPresent())
                vendorServices.setVendor(vendorOptional.get());
            else
                throw new Exception("Vendor not found");

            vendorServices.setServiceAmount(addServiceRequest.getServiceAmount());
            vendorServices.setServiceLocation(addServiceRequest.getServiceLocation());
            vendorServices.setServiceTitle(addServiceRequest.getServiceTitle());
            vendorServices.setDescriptions(addServiceRequest.getDescriptions());

            Set<ServiceOffer> serviceOffers = new HashSet<>();
            for (int i = 0; i < addServiceRequest.getServiceOfferedDtos().size(); i++) {
                ServiceOffer serviceOffer = new ServiceOffer();
                serviceOffer.setServiceOffered(addServiceRequest.getServiceOfferedDtos().get(i).getServiceOffered());
                serviceOffer.setCreatedAt(LocalDateTime.now().toString());
                vendorServices.addService(serviceOffer);
                serviceOffers.add(serviceOffer);
            }
            VendorServices savedService = vendorServiceRepo.save(vendorServices);
            response = new Response("Success", "201", "Service added successfully", savedService);
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response getService(Long vendorId) {
        Response response = null;
        try {
            List<VendorServices> vendorServices = vendorServiceRepo.findByVendorId(vendorId);

            List<VendorServicesResponse> actualResponse = new ArrayList<>();
            vendorServices.forEach(vendorService -> {
                VendorServicesResponse vendorServicesResponse = new VendorServicesResponse();
                Set<ServiceOfferedDto> serviceOfferedDto = new HashSet<>();
                vendorService.getServiceOffered().forEach(service -> {
                    ServiceOfferedDto serviceOffer = new ServiceOfferedDto();
                    serviceOffer.setServiceOffered(service.getServiceOffered());
                    serviceOfferedDto.add(serviceOffer);
                });
                vendorServicesResponse.setServiceOffered(serviceOfferedDto);
                vendorServicesResponse.setVendorId(vendorId);
                vendorServicesResponse.setServiceAmount(vendorService.getServiceAmount());
                vendorServicesResponse.setServiceLocation(vendorService.getServiceLocation());
                vendorServicesResponse.setServiceTitle(vendorService.getServiceTitle());
                vendorServicesResponse.setCategory(vendorService.getCategory().getName());
                vendorServicesResponse.setDescriptions(vendorService.getDescriptions());
                vendorServicesResponse.setSubcategory(vendorService.getSubCategory().getName());
                actualResponse.add(vendorServicesResponse);
            });

            response = new Response("Success", "200", "VendorServices fetched successfully", actualResponse);
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }

        return response;
    }

    @Override
    public Response getServiceDetails(Long vendorId, Long vendorServiceId) {
        Response response = null;
        try {
            Optional<VendorServices> vendorServices = vendorServiceRepo.findByIdAndVendorId(vendorServiceId, vendorId);
            if (vendorServices.isPresent()) {
                VendorServices vendorService = vendorServices.get();
                Set<ServiceOfferedDto> serviceOfferedDtos = new HashSet<>();
                vendorService.getServiceOffered().forEach(serviceOffer -> {
                    ServiceOfferedDto serviceOfferedDto = new ServiceOfferedDto();
                    serviceOfferedDto.setServiceOffered(serviceOffer.getServiceOffered());
                    serviceOfferedDtos.add(serviceOfferedDto);
                });
                VendorServicesResponse vendorServicesResponse = new VendorServicesResponse();
                vendorServicesResponse.setServiceOffered(serviceOfferedDtos);
                vendorServicesResponse.setVendorId(vendorId);
                vendorServicesResponse.setServiceAmount(vendorService.getServiceAmount());
                vendorServicesResponse.setServiceLocation(vendorService.getServiceLocation());
                vendorServicesResponse.setServiceTitle(vendorService.getServiceTitle());
                vendorServicesResponse.setCategory(vendorService.getCategory().getName());
                vendorServicesResponse.setDescriptions(vendorService.getDescriptions());
                vendorServicesResponse.setSubcategory(vendorService.getSubCategory().getName());
                response = new Response("Success", "200", "VendorServiceDetails fetched successfully", vendorServicesResponse);

            } else {
                response = new Response("Success", "404", "VendorServiceDetails notFound", null);

            }


        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }

        return response;
    }

    @Override
    public Response getAllServices(Integer pageNumber,Integer pageSize,String sortBy,String sortDir) {
        Response response = null;
        try {
            //Sort sort=null;
            Sort sort=sortDir.equalsIgnoreCase("asc")?Sort.by(sortBy).ascending():Sort.by(sortBy).descending();
//            if (sortDir.equalsIgnoreCase("asc")){
//                sort=Sort.by(sortBy).ascending();
//            }
//            else {-
//                sort=Sort.by(sortBy).descending();
//            }
            Pageable pageable= PageRequest.of(pageNumber,pageSize, sort);
            //Pageable pageable= PageRequest.of(pageNumber,pageSize, Sort.by(sortBy).descending());
            Page<VendorServices> vendorServicesPage= vendorServiceRepo.findAll(pageable);
//            List<VendorServices> vendorServices = vendorServiceRepo.findAll();
            List<VendorServices> vendorServices = vendorServicesPage.getContent();
            List<VendorServicesResponse> actualResponse = new ArrayList<>();
            vendorServices.forEach(vendorService -> {
                VendorServicesResponse vendorServicesResponse = new VendorServicesResponse();
                Set<ServiceOfferedDto> serviceOfferedDto = new HashSet<>();
                vendorService.getServiceOffered().forEach(service -> {
                    ServiceOfferedDto serviceOffer = new ServiceOfferedDto();
                    serviceOffer.setServiceOffered(service.getServiceOffered());
                    serviceOfferedDto.add(serviceOffer);
                });
                vendorServicesResponse.setServiceOffered(serviceOfferedDto);
                vendorServicesResponse.setVendorId(vendorService.getVendor().getId());
                vendorServicesResponse.setServiceAmount(vendorService.getServiceAmount());
                vendorServicesResponse.setServiceLocation(vendorService.getServiceLocation());
                vendorServicesResponse.setServiceTitle(vendorService.getServiceTitle());
                vendorServicesResponse.setCategory(vendorService.getCategory().getName());
                vendorServicesResponse.setDescriptions(vendorService.getDescriptions());
                vendorServicesResponse.setSubcategory(vendorService.getSubCategory().getName());
                actualResponse.add(vendorServicesResponse);
            });
            response = new Response("Success", "200", "All Services fetched successfully", actualResponse);
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;
    }

    @Override
    public Response getSubscriptions(Long vendorId) {
        Response response = null;
        try {
            Optional<Subscription> subscriptionOptional=subscriptionRepo.findByVendorIdAndStatus(vendorId,Status.ACTIVE);
            if (subscriptionOptional.isPresent()) {
                Subscription subscription = subscriptionOptional.get();
                response = new Response("Success", "200", "Subscriptions Details ", subscription);

            }
            else {
                response = new Response("Success", "200", "Subscriptions Details ", null);

            }

        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);

        }

        return response;
    }


    @Override
    public Response searchVendorServices(String keyword) {
        Response response=null;
        try {
            List<VendorServices> vendorServices = this.vendorServiceRepo.findByServiceTitleContaining(keyword);
         response=new Response("Success","200","VendorServices Fetched Successfully",vendorServices);
        }
        catch (Exception exception){
            response = new Response("Failure", "500", exception.getMessage(), null);

        }
        return response;
    }



    @Override
    public Response addSubscriptions(SubscriptionRequest subscriptionRequest) {
        Response response = null;
        try {
            Optional<Subscription> subscriptionOptional = subscriptionRepo.findByVendorIdAndStatus(subscriptionRequest.getPlanId(), Status.ACTIVE);
            if (subscriptionOptional.isPresent()) {
                //Inactive old plan
                //360 and 367
                Subscription subscription = subscriptionOptional.get();
                subscription.setStatus(Status.IN_ACTIVE);
                subscription.setUpdatedAt(LocalDateTime.now().toString());
                subscriptionRepo.save(subscription);

                //adding new plan
                Subscription subscriptionData = addNewSubscription(subscriptionRequest);
                response = new Response("Success", "200", "Subscriptions Details ", subscriptionData);
            } else {
                //adding new plan
                Subscription subscriptionData = addNewSubscription(subscriptionRequest);
                response = new Response("Success", "200", "Subscriptions Details ", subscriptionData);
            }
        } catch (Exception exception) {
            response = new Response("Failure", "500", exception.getMessage(), null);
        }
        return response;

    }

    private Subscription addNewSubscription(SubscriptionRequest subscriptionRequest) throws Exception {
        Subscription subscription = new Subscription();

        //finding and setting vendor details
        Optional<Vendor> vendorOptional = vendorRepo.findById(subscriptionRequest.getVendorId());
        if (vendorOptional.isPresent())
            subscription.setVendor(vendorOptional.get());
        else
            throw new Exception("Vendor not found");

        // finding and setting plan details
        Optional<SubscriptionsPlan> subscriptionsPlanOptional = subscriptionsPlanRepo.findById(subscriptionRequest.getPlanId());
        if (subscriptionsPlanOptional.isPresent())
            subscription.setSubscriptionsPlan(subscriptionsPlanOptional.get());
        else
            throw new Exception("Subscription plan not found");

        //setting other fields
        subscription.setPaymentMethod(subscriptionRequest.getPaymentMethod());
        subscription.setCreatedAt(LocalDateTime.now().toString());
        subscription.setStatus(Status.ACTIVE);

        //adding data in database
        Subscription subscriptionData = subscriptionRepo.save(subscription);
        return subscriptionData;
    }
}
