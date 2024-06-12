package com.sc.scg.lb;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@SuppressWarnings("unused")
@Slf4j
public class ServiceDiscovery {
    private final DiscoveryClient discoveryClient;

    @Autowired
    public ServiceDiscovery(DiscoveryClient discoveryClient) {
        this.discoveryClient = discoveryClient;
    }

    public void getServiceInstances(String serviceId) {

        List<ServiceInstance> instances = discoveryClient.getInstances(serviceId);

        if (instances.isEmpty()) {
            log.info("No instances found for service: {}", serviceId);
        } else {
            log.info("Instances of {}", serviceId);
            for (ServiceInstance instance : instances) {
                log.info("Instance ID: {}", instance.getInstanceId());
                log.info("Host: {}", instance.getHost());
                log.info("Port: {}", instance.getPort());
                log.info("URI: {}", instance.getUri());
                log.info("---");
            }
        }
    }
}