#---------------------------------------------------------------------------------
# Clear the implicit built in rules
#---------------------------------------------------------------------------------
.SUFFIXES:
#---------------------------------------------------------------------------------
ifeq ($(strip $(DEVKITPPC)),)
$(error "Please set DEVKITPPC in your environment. export DEVKITPPC=<path to>devkitPPC")
endif

include $(DEVKITPPC)/wii_rules

#---------------------------------------------------------------------------------
# TARGET is the name of the output
# BUILD is the directory where object files & intermediate files will be placed
# SOURCES is a list of directories containing source code
# INCLUDES is a list of directories containing extra header files
#---------------------------------------------------------------------------------
TARGET := priiloader_nand
BUILD := build
SOURCES := source
DATA := data
INCLUDES := include

#---------------------------------------------------------------------------------
# MS Visual Studio Style Fix
#---------------------------------------------------------------------------------
STYLEFIX = 2>&1 | sed -e 's/\([a-zA-Z\.]\+\):\([0-9]\+\):\([0-9]\+:\)\?\(.\+\)/\1(\2):\4/' -e 's/undefined/error: undefined/'

#---------------------------------------------------------------------------------
# options for code generation
#---------------------------------------------------------------------------------

CFLAGS = -Os -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wcast-qual -Wshadow -Wformat=2 -Wundef -Werror=float-equal $(MACHDEP) $(INCLUDE)
CXXFLAGS = -std=c++20 $(CFLAGS)

LDFLAGS = $(MACHDEP) -Wl,-Map,$(notdir $@).map,--section-start,.init=0x80005000

#---------------------------------------------------------------------------------
# any extra libraries we wish to link with the project
#---------------------------------------------------------------------------------
LIBS := -ldb -lwiiuse -lbte -logc -lfat

#---------------------------------------------------------------------------------
# list of directories containing libraries, this must be the top level containing
# include and lib
#---------------------------------------------------------------------------------
LIBDIRS :=  $(CURDIR)/libs

#---------------------------------------------------------------------------------
# no real need to edit anything past this point unless you need to add additional
# rules for different file extensions
#---------------------------------------------------------------------------------
ifneq ($(BUILD),$(notdir $(CURDIR)))
#---------------------------------------------------------------------------------

export OUTPUT := $(CURDIR)/$(TARGET)

export VPATH := $(foreach dir,$(SOURCES),$(CURDIR)/$(dir)) \
	$(foreach dir,$(DATA),$(CURDIR)/$(dir))

export DEPSDIR := $(CURDIR)/$(BUILD)

#---------------------------------------------------------------------------------
# automatically build a list of object files for our project
#---------------------------------------------------------------------------------
CFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
sFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))
SFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.S)))
BINFILES := $(foreach dir,$(DATA),$(notdir $(wildcard $(dir)/*.*)))

#---------------------------------------------------------------------------------
# use CXX for linking C++ projects, CC for standard C
#---------------------------------------------------------------------------------
ifeq ($(strip $(CPPFILES)),)
	export LD := $(CC)
else
	export LD := $(CXX)
endif

export OFILES := $(addsuffix .o,$(BINFILES)) \
	$(CPPFILES:.cpp=.o) $(CFILES:.c=.o) \
	$(sFILES:.s=.o) $(SFILES:.S=.o)

#---------------------------------------------------------------------------------
# build a list of include paths
#---------------------------------------------------------------------------------
export INCLUDE := $(foreach dir,$(INCLUDES), -iquote $(CURDIR)/$(dir)) \
	$(foreach dir,$(LIBDIRS),-isystem $(dir)/include) \
	-isystem $(CURDIR)/$(BUILD) \
	-isystem $(LIBOGC_INC)

#---------------------------------------------------------------------------------
# build a list of library paths
#---------------------------------------------------------------------------------
export LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib) -L$(LIBOGC_LIB)

export OUTPUT := $(CURDIR)/$(TARGET)
.PHONY: $(BUILD) clean rebuild

#---------------------------------------------------------------------------------
#build order
all: $(BUILD) run

#run
$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@make --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

#---------------------------------------------------------------------------------
clean:
	@echo clean ...
	@rm -fr $(BUILD) $(OUTPUT).elf $(OUTPUT).dol

rebuild : clean $(BUILD)

#---------------------------------------------------------------------------------
run:
#send elf to the wii
ifneq ($(WIILOAD),)
	wiiload $(TARGET).dol
else
	@echo "wiiload variable not set. skipping sending to homebrew channel (wiiload)"
endif

#---------------------------------------------------------------------------------
else

DEPENDS := $(OFILES:.o=.d)

#---------------------------------------------------------------------------------
# main targets
#---------------------------------------------------------------------------------
$(OUTPUT).dol: $(OUTPUT).elf
$(OUTPUT).elf: $(OFILES)

#---------------------------------------------------------------------------------
# This rule links in binary data with the .bin,tik,tmd & app extension
#---------------------------------------------------------------------------------

%.bin.o : %.bin
#---------------------------------------------------------------------------------
	@echo $(notdir $<)
	$(bin2o)

-include $(DEPENDS)

%.tik.o : %.tik
#---------------------------------------------------------------------------------
	@echo $(notdir $<)
	$(bin2o)

-include $(DEPENDS)

%.tmd.o : %.tmd
#---------------------------------------------------------------------------------
	@echo $(notdir $<)
	$(bin2o)

-include $(DEPENDS)

%.ini.o : %.ini
#---------------------------------------------------------------------------------
	@echo $(notdir $<)
	$(bin2o)

-include $(DEPENDS)

#---------------------------------------------------------------------------------
endif
#---------------------------------------------------------------------------------
