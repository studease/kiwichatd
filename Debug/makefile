################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include src/studease.cn/websocket/subdir.mk
-include src/studease.cn/utils/subdir.mk
-include src/studease.cn/http/subdir.mk
-include src/studease.cn/event/subdir.mk
-include src/studease.cn/core/subdir.mk
-include src/kiwichatd.com/core/subdir.mk
-include src/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: kiwichatd

# Tool invocations
kiwichatd: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	gcc -L/usr/local/ssl/lib -o "kiwichatd" $(OBJS) $(USER_OBJS) $(LIBS) -pthread -lm -march=x86-64
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) kiwichatd
	-@echo ' '

.PHONY: all clean dependents

-include ../makefile.targets
