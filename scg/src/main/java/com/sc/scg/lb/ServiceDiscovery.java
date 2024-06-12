package com.sc.scg.lb;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@SuppressWarnings("unused")
public class ServiceDiscovery {
    private final DiscoveryClient discoveryClient;

    @Autowired
    public ServiceDiscovery(DiscoveryClient discoveryClient) {
        this.discoveryClient = discoveryClient;
    }

    public void getServiceInstances(String serviceId) {

        List<ServiceInstance> instances = discoveryClient.getInstances(serviceId);

        if (instances.isEmpty()) {
            System.out.println("No instances found for service: " + serviceId);
        } else {
            System.out.println("Instances of " + serviceId + ":");
            for (ServiceInstance instance : instances) {
                System.out.println("Instance ID: " + instance.getInstanceId());
                System.out.println("Host: " + instance.getHost());
                System.out.println("Port: " + instance.getPort());
                System.out.println("URI: " + instance.getUri());
                System.out.println("---");
            }
        }
    }
}