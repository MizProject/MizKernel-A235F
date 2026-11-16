# auto-detect subdirs
ifeq ($(CONFIG_ARCH_SDXPOORWILLS), y)
AUDIO_CONF := $(srctree)/techpack/audio/config/sdxpoorwillsauto.conf
include $(AUDIO_CONF)
export $(shell sed -n 's/^\([A-Za-z0-9_]*\)=.*/\1/p' $(AUDIO_CONF))
endif
ifeq ($(CONFIG_ARCH_SM8150), y)
AUDIO_CONF := $(srctree)/techpack/audio/config/sm8150auto.conf
include $(AUDIO_CONF)
export $(shell sed -n 's/^\([A-Za-z0-9_]*\)=.*/\1/p' $(AUDIO_CONF))
endif
ifeq ($(CONFIG_ARCH_SDMSHRIKE), y)
AUDIO_CONF := $(srctree)/techpack/audio/config/sm8150auto.conf
include $(AUDIO_CONF)
export $(shell sed -n 's/^\([A-Za-z0-9_]*\)=.*/\1/p' $(AUDIO_CONF))
endif
ifeq ($(CONFIG_ARCH_KONA), y)
include $(srctree)/techpack/audio/config/konaauto.conf
endif
ifeq ($(CONFIG_ARCH_SDM660), y)
include $(srctree)/techpack/audio/config/sdm660auto.conf
endif
ifeq ($(CONFIG_ARCH_BENGAL), y)
ifeq ($(PROJECT_NAME),$(filter $(PROJECT_NAME),a23))
AUDIO_CONF := $(srctree)/techpack/audio/config/bengal_a23.conf
else
AUDIO_CONF := $(srctree)/techpack/audio/config/bengalauto.conf
endif
include $(AUDIO_CONF)
export $(shell sed -n 's/^\([A-Za-z0-9_]*\)=.*/\1/p' $(AUDIO_CONF))
endif

# Use USERINCLUDE when you must reference the UAPI directories only.
USERINCLUDE     += \
                -I$(srctree)/techpack/audio/include/uapi \
                -I$(srctree)/techpack/audio/include

# Use LINUXINCLUDE when you must reference the include/ directory.
# Needed to be compatible with the O= option
LINUXINCLUDE    += \
                -I$(srctree)/techpack/audio/include/uapi \
                -I$(srctree)/techpack/audio/include

ifeq ($(CONFIG_ARCH_SDXPOORWILLS), y)
LINUXINCLUDE    += \
                -include $(srctree)/techpack/audio/config/sdxpoorwillsautoconf.h
endif
ifeq ($(CONFIG_ARCH_SM8150), y)
LINUXINCLUDE    += \
                -include $(srctree)/techpack/audio/config/sm8150autoconf.h
endif
ifeq ($(CONFIG_ARCH_SDMSHRIKE), y)
LINUXINCLUDE    += \
                -include $(srctree)/techpack/audio/config/sm8150autoconf.h
endif
ifeq ($(CONFIG_ARCH_KONA), y)
LINUXINCLUDE    += \
                -include $(srctree)/techpack/audio/config/konaautoconf.h
endif
ifeq ($(CONFIG_ARCH_SDM660), y)
LINUXINCLUDE    += \
                -include $(srctree)/techpack/audio/config/sdm660autoconf.h
endif
ifeq ($(CONFIG_ARCH_BENGAL), y)
ifeq ($(PROJECT_NAME),$(filter $(PROJECT_NAME),a23))
LINUXINCLUDE    += \
                -include $(srctree)/techpack/audio/config/bengal_a23.h
else
LINUXINCLUDE    += \
                -include $(srctree)/techpack/audio/config/bengalautoconf.h
endif
endif
obj-y += soc/
obj-y += dsp/
obj-y += ipc/
obj-y += asoc/
