package com.felip.rbac;

import org.springframework.boot.SpringApplication;

public class TestRbacApplication {

	public static void main(String[] args) {
		SpringApplication.from(RbacApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
