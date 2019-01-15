/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <net/socket.h>
#include <coap_api.h>

#define APP_COAP_TICK_INTERVAL_MS 1000
#define APP_COAP_LOCAL_CLIENT_PORT 9685
#define APP_COAP_LOCAL_SECURE_CLIENT_PORT 9785
#define APP_COAP_REMOTE_SERVER_PORT 5683
#define APP_COAP_REMOTE_SECURE_SERVER_PORT 5684

#define APP_MAX_AT_READ_LENGTH 100
#define APP_MAX_AT_WRITE_LENGTH 100

/** Tag used to identify security credentials used by the client. */
#define APP_COAP_SEC_TAG 2018

/** Client identity used for DTLS. */
#define APP_COAP_SEC_IDENTITY "Client_identity"

/** Pre-shared key used for DTLS. */
#define APP_COAP_SEC_PSK ((u8_t []){ 0x73, 0x65, 0x63, 0x72, 0x65, \
				     0x74, 0x50, 0x54, 0x4b, 0x30 })

#define APP_COMMAND_TOGGLE '2'

static const char uri_part_lights[] = "lights";
static const char uri_part_led3[] = "led3";
static u16_t global_token_count = 0x0102;

static struct k_delayed_work tick;
static bool tick_fired;

static struct sockaddr_in coap_server;
static struct sockaddr_in coap_secure_server;

/** Transport handle used for data exchange, obtained on @coap_init. */
static coap_transport_handle_t transport_handle;

/** Transport handle used for secure data exchange, obtained on
 *  @coap_security_setup.
 */
static coap_transport_handle_t secure_transport_handle;

static void app_coap_request_send(void);
static void app_coap_secure_request_send(void);

static struct pollfd fds[4];
static int nfds;

#define APP_ERROR_CHECK(error_code) \
	do { \
		if (error_code != 0) { \
			printf("Error: %d\n", error_code); \
			while (1) \
				; \
		} \
	} while (0)


static void wait(int timeout)
{
	if (nfds > 0) {
		if (poll(fds, nfds, timeout) < 0) {
			printk("poll error: %d\n", errno);
		}
	}
}

/**@brief Recoverable BSD library error. */
void bsd_recoverable_error_handler(u32_t error)
{
	(void)error;

	while (true) {
		;
	}
}

/**@brief Irrecoverable BSD library error. */
void bsd_irrecoverable_error_handler(u32_t error)
{
	(void)error;

	while (true) {
		;
	}
}

#if 0
/**@brief Function to configure the modem and create a LTE connection. */
static void app_modem_configure(void)
{
	int at_socket_fd = -1;
	int bytes_written = 0;
	int bytes_read = 0;
	char read_buffer[APP_MAX_AT_READ_LENGTH];

	at_socket_fd = socket(AF_LTE, 0, NPROTO_AT);
	APP_ERROR_CHECK_BOOL(at_socket_fd >= 0);

	bytes_written = write(at_socket_fd, "AT+CEREG=2", 10);
	APP_ERROR_CHECK_BOOL(bytes_written == 10);

	bytes_read = read(at_socket_fd, read_buffer, APP_MAX_AT_READ_LENGTH);
	APP_ERROR_CHECK_BOOL(bytes_read >= 2);
	APP_ERROR_CHECK_BOOL(strncmp("OK", read_buffer, 2) == 0);

	bytes_written = write(at_socket_fd, "AT+CFUN=1", 9);
	APP_ERROR_CHECK_BOOL(bytes_written == 9);

	bytes_read = read(at_socket_fd, read_buffer, APP_MAX_AT_READ_LENGTH);
	APP_ERROR_CHECK_BOOL(bytes_read >= 2);
	APP_ERROR_CHECK_BOOL(strncmp("OK", read_buffer, 2) == 0);

	while (true) {
		bytes_read = read(at_socket_fd, read_buffer,
				  APP_MAX_AT_READ_LENGTH);

		if ((strncmp("+CEREG: 1", read_buffer, 9) == 0) ||
		    (strncmp("+CEREG:1", read_buffer, 8) == 0)) {
			break;
		}
	}
	UNUSED_RETURN_VALUE(close(at_socket_fd));
}

/**@brief Function to provision credentials used for secure transport
 *        by the CoAP client.
 */
static void app_provision(void)
{
	int at_socket_fd = -1;
	int bytes_written = 0;
	int bytes_read = 0;

	char write_buffer[APP_MAX_AT_WRITE_LENGTH];
	char read_buffer[APP_MAX_AT_READ_LENGTH];

	at_socket_fd = socket(AF_LTE, 0, NPROTO_AT);
	APP_ERROR_CHECK_BOOL(at_socket_fd >= 0);

    #define WRITE_OPCODE  0
    #define IDENTITY_CODE 4
    #define PSK_CODE      3

	memset(write_buffer, 0, APP_MAX_AT_WRITE_LENGTH);
	UNUSED_RETURN_VALUE(snprintf(write_buffer,
				     APP_MAX_AT_WRITE_LENGTH,
				     "AT%%CMNG=%d,%d,%d,%s",
				     WRITE_OPCODE,
				     APP_COAP_SEC_TAG,
				     IDENTITY_CODE,
				     APP_COAP_SEC_IDENTITY));

	bytes_written = write(at_socket_fd, write_buffer, strlen(write_buffer));
	APP_ERROR_CHECK_BOOL(bytes_written == strlen(write_buffer));

	bytes_read = read(at_socket_fd, read_buffer, APP_MAX_AT_READ_LENGTH);
	APP_ERROR_CHECK_BOOL(bytes_read >= 2);
	APP_ERROR_CHECK_BOOL(strncmp("OK", read_buffer, 2) == 0);

	memset(write_buffer, 0, APP_MAX_AT_WRITE_LENGTH);
	UNUSED_RETURN_VALUE(snprintf(write_buffer,
				     APP_MAX_AT_WRITE_LENGTH,
				     "AT%%CMNG=%d,%d,%d,\"%s\"",
				     WRITE_OPCODE,
				     APP_COAP_SEC_TAG,
				     PSK_CODE,
				     APP_COAP_SEC_PSK));

	bytes_written = write(at_socket_fd, write_buffer, strlen(write_buffer));
	APP_ERROR_CHECK_BOOL(bytes_written == strlen(write_buffer));

	bytes_read = read(at_socket_fd, read_buffer, APP_MAX_AT_READ_LENGTH);
	APP_ERROR_CHECK_BOOL(bytes_read >= 2);
	APP_ERROR_CHECK_BOOL(strncmp("OK", read_buffer, 2) == 0);

	UNUSED_RETURN_VALUE(close(at_socket_fd));
}
#endif

/**@brief Function for catering CoAP module with periodic time ticks. */
static void app_coap_time_tick(struct k_work *work)
{
	ARG_UNUSED(work);

	tick_fired = true;

	k_delayed_work_submit(&tick, K_MSEC(APP_COAP_TICK_INTERVAL_MS));
}

static void tick_handler(void)
{
	static int send_counter;

	(void)coap_time_tick();

	if (send_counter == 0) {
		app_coap_request_send();
		app_coap_secure_request_send();
	}

	send_counter = (send_counter + 1) % 5;
}

static void app_process(void)
{
	if (tick_fired) {
		tick_fired = false;
		tick_handler();
	}

	wait(1000);
	coap_transport_input();
}

/**@brief Handles an errors notified by CoAP. */
static void app_coap_error_handler(u32_t error_code, coap_message_t *message)
{
	ARG_UNUSED(message);

	printf("CoAP error handler: error_code: %u\n", error_code);
}

/**@brief Handles responses from the remote CoAP server. */
static void app_coap_response_handle(u32_t status, void *arg,
				     coap_message_t *response)
{
	printf("CoAP response: status: 0x%x", status);

	if (status == 0) {
		printf(", token 0x%02x%02x", response->token[0],
		       response->token[1]);
	}

	printf("\n");
}

/**@brief Handles responses from the remote CoAP server. */
static void app_coaps_response_handle(u32_t status, void *arg,
				      coap_message_t *response)
{
	printf("CoAPs secure response: status: 0x%x", status);

	if (status == 0) {
		printf(", token 0x%02x%02x", response->token[0],
		       response->token[1]);
	}

	printf("\n");
}

/**@brief Method to send request as a client to a remote server. */
static void app_coap_request_send(void)
{
	u32_t err_code;
	coap_message_t *p_request;
	coap_message_conf_t message_conf;

	memset(&message_conf, 0x00, sizeof(message_conf));
	message_conf.type = COAP_TYPE_CON;
	message_conf.code = COAP_CODE_PUT;
	message_conf.transport = transport_handle;
	message_conf.id = 0; /* Auto-generate message ID. */

	message_conf.token[0] = (global_token_count >> 8) & 0xFF;
	message_conf.token[1] = global_token_count & 0xFF;
	global_token_count++;

	message_conf.token_len = 2;
	message_conf.response_callback = app_coap_response_handle;
	message_conf.transport = transport_handle;

	err_code = coap_message_new(&p_request, &message_conf);
	if (err_code != 0) {
		printf("Failed to allocate CoAP request message!\n");
		return;
	}

	err_code = coap_message_remote_addr_set(
					p_request,
					(struct sockaddr *)&coap_server);
	APP_ERROR_CHECK(err_code);

	err_code = coap_message_opt_str_add(p_request, COAP_OPT_URI_PATH,
					    (u8_t *)uri_part_lights,
					    strlen(uri_part_lights));
	APP_ERROR_CHECK(err_code);

	err_code = coap_message_opt_str_add(p_request, COAP_OPT_URI_PATH,
					    (u8_t *)uri_part_led3,
					    strlen(uri_part_led3));
	APP_ERROR_CHECK(err_code);

	u8_t payload[] = { APP_COMMAND_TOGGLE };

	err_code = coap_message_payload_set(p_request, payload,
					    sizeof(payload));
	APP_ERROR_CHECK(err_code);

	u32_t handle;

	err_code = coap_message_send(&handle, p_request);
	APP_ERROR_CHECK(err_code);

	printf("CoAP request sent: token 0x%02x%02x\n",
	       p_request->token[0], p_request->token[1]);

	err_code = coap_message_delete(p_request);
	APP_ERROR_CHECK(err_code);
}


/**@brief Method to send request as a client to a remote server. */
static void app_coap_secure_request_send(void)
{
	u32_t err_code;
	coap_message_t *p_request;
	coap_message_conf_t message_conf;

	memset(&message_conf, 0x00, sizeof(message_conf));
	message_conf.type = COAP_TYPE_CON;
	message_conf.code = COAP_CODE_PUT;
	message_conf.transport = secure_transport_handle;
	message_conf.id = 0; /* Auto-generate message ID. */

	message_conf.token[0] = (global_token_count >> 8) & 0xFF;
	message_conf.token[1] = global_token_count & 0xFF;
	global_token_count++;

	message_conf.token_len = 2;
	message_conf.response_callback = app_coaps_response_handle;
	message_conf.transport = secure_transport_handle;

	err_code = coap_message_new(&p_request, &message_conf);
	if (err_code != 0) {
		printf("Failed to allocate secure CoAP request message!\n");
		return;
	}

	err_code = coap_message_remote_addr_set(
					p_request,
					(struct sockaddr *)&coap_secure_server);
	APP_ERROR_CHECK(err_code);

	err_code = coap_message_opt_str_add(p_request, COAP_OPT_URI_PATH,
					    (u8_t *)uri_part_lights,
					    strlen(uri_part_lights));
	APP_ERROR_CHECK(err_code);

	err_code = coap_message_opt_str_add(p_request, COAP_OPT_URI_PATH,
					    (u8_t *)uri_part_led3,
					    strlen(uri_part_led3));
	APP_ERROR_CHECK(err_code);

	u8_t payload[] = { APP_COMMAND_TOGGLE };

	err_code = coap_message_payload_set(p_request, payload,
					    sizeof(payload));
	APP_ERROR_CHECK(err_code);

	u32_t handle;

	err_code = coap_message_send(&handle, p_request);
	APP_ERROR_CHECK(err_code);

	printf("CoAPs secure request sent: token 0x%02x%02x\n",
	       p_request->token[0], p_request->token[1]);

	err_code = coap_message_delete(p_request);
	APP_ERROR_CHECK(err_code);
}

/**@brief Initialize CoAP. */
static void app_coap_init(void)
{
	const struct sockaddr_in client_addr = {
		.sin_port = APP_COAP_LOCAL_CLIENT_PORT,
		.sin_family = AF_INET,
		.sin_addr.s_addr = 0
	};

	struct sockaddr *p_localaddr = (struct sockaddr *)&client_addr;

	coap_local_t local_port_list[COAP_PORT_COUNT] = {
		{
			.p_addr = p_localaddr,
			.protocol = IPPROTO_UDP,
			.p_setting = NULL
		}
	};

	coap_transport_init_t port_list;

	port_list.p_port_table = &local_port_list[0];

	int err_code = coap_init(829131, &port_list, k_malloc, k_free);

	if (err_code != 0) {
		printf("Failed to initialize CoAP\n");
		APP_ERROR_CHECK(err_code);
	}

	transport_handle = local_port_list[0].transport;

	/* NOTE: transport_handle is the socket descriptor. */
	fds[nfds].fd = transport_handle;
	fds[nfds].events = POLLIN;
	nfds++;

	err_code = coap_error_handler_register(app_coap_error_handler);
	if (err_code != 0) {
		printf("Failed to register CoAP error handler\n");
		APP_ERROR_CHECK(err_code);
	}
}


/**@brief Function to establish secure transport for the CoAP client. */
static void app_coap_security_setup(void)
{
	const struct sockaddr_in client_addr = {
		.sin_port = APP_COAP_LOCAL_SECURE_CLIENT_PORT,
		.sin_family = AF_INET,
		.sin_addr.s_addr = 0
	};


	struct sockaddr *p_localaddr = (struct sockaddr *)&client_addr;
	sec_tag_t sec_tag_list[] = { APP_COAP_SEC_TAG };

	coap_sec_config_t setting = {
		.role = 0, /* 0 -> Client role */
		.sec_tag_count = ARRAY_SIZE(sec_tag_list),
		.p_sec_tag_list = &sec_tag_list[0]
	};

	coap_local_t local_port = {
		.p_addr = p_localaddr,
		.p_setting = &setting,
		.protocol = IPPROTO_DTLS_1_2
	};

	u32_t err_code = coap_security_setup(
					&local_port,
					(struct sockaddr *)&coap_secure_server);
	APP_ERROR_CHECK(err_code);

	secure_transport_handle = local_port.transport;

	/* NOTE: transport_handle is the socket descriptor. */
	fds[nfds].fd = *(int *)secure_transport_handle;
	fds[nfds].events = POLLIN;
	nfds++;
}

static void peer_init(void)
{
	coap_server.sin_family = AF_INET;
	coap_server.sin_port = htons(APP_COAP_REMOTE_SERVER_PORT);
	inet_pton(AF_INET, CONFIG_NET_CONFIG_PEER_IPV4_ADDR,
		  &coap_server.sin_addr);

	coap_secure_server.sin_family = AF_INET;
	coap_secure_server.sin_port = htons(APP_COAP_REMOTE_SECURE_SERVER_PORT);
	inet_pton(AF_INET, CONFIG_NET_CONFIG_PEER_IPV4_ADDR,
		  &coap_secure_server.sin_addr);
}

static void tls_init(void)
{
	int err_code = tls_credential_add(APP_COAP_SEC_TAG,
					  TLS_CREDENTIAL_PSK,
					  APP_COAP_SEC_PSK,
					  sizeof(APP_COAP_SEC_PSK));
	if (err_code != 0) {
		printf("Failed to register PSK: %d\n", err_code);
		APP_ERROR_CHECK(err_code);
	}

	err_code = tls_credential_add(APP_COAP_SEC_TAG,
				      TLS_CREDENTIAL_PSK_ID,
				      APP_COAP_SEC_IDENTITY,
				      sizeof(APP_COAP_SEC_IDENTITY));
	if (err_code != 0) {
		printf("Failed to register PSK ID: %d\n", err_code);
		APP_ERROR_CHECK(err_code);
	}
}

/**@brief Function for application main entry. */
int main(void)
{
	printf("CoAP application start\n");

	k_delayed_work_init(&tick, app_coap_time_tick);

	peer_init();
	tls_init();
	app_coap_init();
	app_coap_security_setup();

	k_delayed_work_submit(&tick, K_MSEC(APP_COAP_TICK_INTERVAL_MS));

	/* Enter main loop. */
	while (true) {
		app_process();
	}
}
