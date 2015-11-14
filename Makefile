obj-m	+=	firewall.o
#gatemodule-objs := gateway.o

KDIR	:=	/lib/modules/$(shell uname -r)/build
pwd	:=	$(shell pwd)

default:
	$(MAKE)	-C	$(KDIR)	M=$(pwd)	modules
clean:
	make	-C	$(KDIR)	M=$(pwd)	clean

