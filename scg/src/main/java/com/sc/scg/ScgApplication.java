package com.sc.scg;

import com.sc.scg.lb.ServiceDiscovery;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.ApplicationContext;

@SpringBootApplication
@EnableDiscoveryClient
public class ScgApplication {
    public static void main(String[] args) {
        ApplicationContext context = SpringApplication.run(ScgApplication.class, args);

        ServiceDiscovery serviceDiscovery = context.getBean(ServiceDiscovery.class);
        serviceDiscovery.getServiceInstances("member-service");
    }
}
