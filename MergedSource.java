// File: eureka/build.gradle
dependencies {
    implementation 'org.springframework.cloud:spring-cloud-starter-netflix-eureka-server'
}


// File: eureka/build/resources/main/application-eureka2.yml
server:
  port: 8762
eureka:
  client:
    serviceUrl:
      defaultZone: http://${eureka.instance.hostname}:8761/eureka/

// File: eureka/build/resources/main/application-eureka1.yml
server:
  port: 8761
eureka:
  client:
    serviceUrl:
      defaultZone: http://${eureka.instance.hostname}:8762/eureka/

// File: eureka/build/resources/main/application.yml
server:
  port: ${server.port:8761}
spring:
  application:
    name: eureka
eureka:
  instance:
    hostname: ${EUREKA_HOST:localhost}  #Eureka 서버 Host
  client:
    registerWithEureka: false   #Eureka서버 자신을 Service Registry에 등록할지 여부
    fetchRegistry: false        #Service registry를 다른 곳에서 가져올 지 여부.Eureka가 Service Registry이므로 false
    serviceUrl:
      defaultZone: ${eureka.client.serviceUrl.defaultZone}
  server:
    enableSelfPreservation: true    #등록된 service의 일시적 장애일때 service registry에서 제거 안함
    eviction-interval-timer-in-ms: 60000  #지정된 시간마다 유효하지 않은 service를 service registry에서 제거


// File: eureka/src/main/resources/application-eureka2.yml
server:
  port: 8762
eureka:
  client:
    serviceUrl:
      defaultZone: http://${eureka.instance.hostname}:8761/eureka/

// File: eureka/src/main/resources/application-eureka1.yml
server:
  port: 8761
eureka:
  client:
    serviceUrl:
      defaultZone: http://${eureka.instance.hostname}:8762/eureka/

// File: eureka/src/main/resources/application.yml
server:
  port: ${server.port:8761}
spring:
  application:
    name: eureka
eureka:
  instance:
    hostname: ${EUREKA_HOST:localhost}  #Eureka 서버 Host
  client:
    registerWithEureka: false   #Eureka서버 자신을 Service Registry에 등록할지 여부
    fetchRegistry: false        #Service registry를 다른 곳에서 가져올 지 여부.Eureka가 Service Registry이므로 false
    serviceUrl:
      # 여러대의 Eureka서버가 있는 경우 반드시 자신을 제외한 다른 Eureka서버 주소(들)만 지정해야 함
      # k8s배포시에는 service오브젝트 이용하여 설정하면 자동으로 자신을 제외한 다른 서버를 찾음
      defaultZone: ${eureka.client.serviceUrl.defaultZone}
  server:
    enableSelfPreservation: true    #등록된 service의 일시적 장애일때 service registry에서 제거 안함
    eviction-interval-timer-in-ms: 60000  #지정된 시간마다 유효하지 않은 service를 service registry에서 제거


// File: eureka/src/main/java/com/sc/eureka/EurekaApplication.java
package com.sc.eureka;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

@SpringBootApplication
@EnableEurekaServer
public class EurekaApplication {
    public static void main(String[] args) {
        SpringApplication.run(EurekaApplication.class, args);
    }
}


// File: /Users/ondal/workspace/sc/settings.gradle
rootProject.name = 'sc'
include 'config'
include 'eureka'



// File: /Users/ondal/workspace/sc/build.gradle
plugins {
	id 'java'
	id 'org.springframework.boot' version '3.2.6'
	id 'io.spring.dependency-management' version '1.1.5'
}

allprojects {
	group = 'com.cna'
	version = '0.0.1-SNAPSHOT'

	apply plugin: 'java'
	apply plugin: 'io.spring.dependency-management'

	java {
		sourceCompatibility = '17'
	}

	repositories {
		mavenCentral()
	}

	dependencies {
		implementation 'org.springframework.boot:spring-boot-starter'

		testImplementation 'org.springframework.boot:spring-boot-starter-test'
		testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
	}

	dependencyManagement {
		imports {
			mavenBom "org.springframework.cloud:spring-cloud-dependencies:2023.0.2"
		}
	}

	tasks.named('test') {
		useJUnitPlatform()
	}
}

subprojects {
	apply plugin: 'org.springframework.boot'
}



