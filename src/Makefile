
include ../vsn.mk
VSN=$(PRAN_VSN)

MODULES=pran \
	pran_ethernet \
	pran_ip \
	pran_pcap \
	pran_pcap_file \
	pran_sip \
	pran_tcp \
	pran_tcp_udp_utils \
	pran_udp \
	pran_utils \
	pran_mtp3 \
	pran_sccp \
	rfc2806 \
	rfc3261 \
	rfc4234_core

ABNF_MODULES = rfc2806 \
	rfc3261 \
	rfc4234_core

EBIN_FILES:=$(MODULES:%=../ebin/%.beam)
ERL_FILES:=$(MODULES:%=%.erl)

EBIN_DIR := ../ebin
INCL_LIB := ../include

#ABNFC := $ABNFC/bin/abnfc
#ABNFC_FLAGS= -binary -o ../ebin/

ERLC_FLAGS+=-W -I $(INCL_LIB)

INCLUDES=$(INCL_LIB)/elibpcap.hrl

#
# Targets
#

all: $(EBIN_FILES)

debug:
	$(MAKE) ERLC_FLAGS+="$(ERLC_FLAGS) +debug_info -Ddebug"

docs: ../doc/index.html

../doc/index.html: ../doc/overview.edoc $(ERL_FILES)  $(INCLUDES)
	erl -noshell -run edoc_run application "pran" '".."' '[]'

clean:
	rm -f $(EBIN_FILES) ../doc/*.html ../doc/edoc-info \
	../doc/stylesheet.css ../doc/erlang.png

$(EBIN_DIR)/%.beam: %.erl $(INCLUDES)
	erlc $(ERLC_FLAGS) -o ../ebin $<

$(EBIN_DIR)/%.beam: %.abnf
	$(ABNFC) $(ABNFC_FLAGS) $<