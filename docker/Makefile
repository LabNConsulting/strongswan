SHELL := /bin/bash
ifeq ($(CI_REGISTRY),)
BUILDIMAGE ?= labn/docker-ci-test:18.04
else
BUILDIMAGE ?= $(CI_REGISTRY)/labn/docker-ci-test:18.04
endif
USERID := $(shell id -u)

CFG_CFLAGS := -g -O0 -Wall -Wno-format -Wno-format-security -Wno-pointer-sign

# Below is not used by CI.

VPPINSTDIR ?= $(shell cd $(CURDIR)/../../vpp/build-root/install-vpp_debug-native/vpp && pwd)

autoconf:
	test -d $(VPPINSTDIR)
	echo VPPINSTDIR: $(VPPINSTDIR)
	(cd .. && docker run -i -v $(VPPINSTDIR):/usr/local:ro -v $$(pwd):$$(pwd) --user=$(USERID) --shm-size=$$((512*1024*1024)) $(BUILDIMAGE) bash -c "cd $$(pwd) && autoreconf -i && CFLAGS='$(CFG_CFLAGS)' ./configure --prefix=$(VPPINSTDIR) --disable-kernel-netlink --disable-systemd --with-systemdsystemunitdir=$(VPPINSTDIR)/lib/systemd/system --enable-kernel-vpp --enable-socket-vpp --enable-kernel-libipsec --enable-gcm")

build:
	(cd .. && docker run -i -v $(VPPINSTDIR):/usr/local:ro -v $$(pwd):$$(pwd) --user=$(USERID) --shm-size=$$((512*1024*1024)) $(BUILDIMAGE) bash -c "cd $$(pwd) && make")

install:
	(cd .. && docker run -i -v $(VPPINSTDIR):$(VPPINSTDIR) -v $(VPPINSTDIR):/usr/local:ro -v $$(pwd):$$(pwd) --user=$(USERID) --shm-size=$$((512*1024*1024)) $(BUILDIMAGE) bash -c "cd $$(pwd) && make install")

distclean:
	(cd .. && docker run -i -v $(VPPINSTDIR):/usr/local:ro -v $$(pwd):$$(pwd) --user=$(USERID) --shm-size=$$((512*1024*1024)) $(BUILDIMAGE) bash -c "cd $$(pwd) && make distclean")
