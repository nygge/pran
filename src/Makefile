
include ../vsn.mk
VSN=$(PRAN_VSN)

MODULES=pran \
	pran_ethernet \
	pran_ip \
	pran_pcap \
	pran_pcap_file \
	pran_sdp \
	pran_sip \
	pran_tcp \
	pran_tcp_udp_utils \
	pran_udp \
	pran_utils \
	pran_mtp2 \
	pran_mtp3 \
	pran_sccp \
	rfc2806 \
	rfc3261 \
	rfc4234_core \
	rfc4566 \
	sip_tracer

ABNF_MODULES = rfc2806 \
	rfc3261 \
	rfc4234_core \
	rfc4566

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

all: $(EBIN_DIR) $(EBIN_FILES)

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

$(EBIN_DIR):
	mkdir $(EBIN_DIR)

$(EBIN_DIR)/pran.beam: $(INCL_LIB)/elibpcap.hrl
$(EBIN_DIR)/pran_ethernet.beam: $(INCL_LIB)/ethernet.hrl
$(EBIN_DIR)/pran_ip.beam: $(INCL_LIB)/ip.hrl
$(EBIN_DIR)/pran_mtp2.beam: $(INCL_LIB)/mtp2.hrl
$(EBIN_DIR)/pran_mtp3.beam: $(INCL_LIB)/mtp3.hrl
$(EBIN_DIR)/pran_pcap.beam: $(INCL_LIB)/elibpcap.hrl
$(EBIN_DIR)/pran_pcap_file.beam: $(INCL_LIB)/elibpcap.hrl
$(EBIN_DIR)/pran_sccp.beam: $(INCL_LIB)/sccp_params.hrl
$(EBIN_DIR)/pran_sccp.beam: $(INCL_LIB)/sccp_pdu.hrl
$(EBIN_DIR)/pran_tcp.beam: $(INCL_LIB)/tcp.hrl
$(EBIN_DIR)/pran_udp.beam: $(INCL_LIB)/udp.hrl
$(EBIN_DIR)/sip_tracer.erl: $(INCL_LIB)/elibpcap.hrl \
	$(INCL_LIB)/ethernet.hrl \
	$(INCL_LIB)/ip.hrl \
	$(INCL_LIB)/tcp.hrl \
	$(INCL_LIB)/udp.hrl
