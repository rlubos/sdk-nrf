#if defined(CONFIG_LWM2M_DTLS_SUPPORT)
#if defined(CONFIG_NET_SOCKETS_OFFLOAD_TLS)
static char client_psk[] = "000102030405060708090a0b0c0d0e0f";
#else
static char client_psk[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
#endif
#endif /* defined(CONFIG_LWM2M_DTLS_SUPPORT) */
