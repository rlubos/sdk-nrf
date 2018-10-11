/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <net/socket.h>
#include <net/tls_credentials.h>
#include <coap_api.h>
#include <coap_observe_api.h>

#define APP_COAP_TICK_INTERVAL_MS 1000
#define APP_COAP_LOCAL_SERVER_PORT 5683
#define APP_COAP_LOCAL_SECURE_SERVER_PORT 5684

/** Tag used to identify security credentials used by the client. */
#define APP_COAP_SEC_TAG 2018

/** Client identity used for DTLS. */
#define APP_COAP_SEC_IDENTITY "Client_identity"

/** Pre-shared key used for DTLS. */
#define APP_COAP_SEC_PSK ((u8_t []){ 0x73, 0x65, 0x63, 0x72, 0x65, \
				     0x74, 0x50, 0x54, 0x4b, 0x30 })

/** Number of seconds prior to a max-age timeout which an updated state of
 *  the observed value should be sent to the observers.
 */
#define OBSERVE_NOTIFY_DELTA_MAX_AGE        2

#define APP_COMMAND_OFF '0'
#define APP_COMMAND_ON '1'
#define APP_COMMAND_TOGGLE '2'

#define LED_ONE BSP_LED_0_MASK /**< Blinking LED. */
#define LED_THREE BSP_LED_2_MASK /**< CoAP LED resource. */

#define APP_MAX_AT_READ_LENGTH 100
#define APP_MAX_AT_WRITE_LENGTH 100

#define LEDS_ON(...) (led_state = true)
#define LEDS_OFF(...) (led_state = false)
#define LEDS_INVERT(...) (led_state = !led_state)
#define LED_IS_ON(...) (led_state)

#define APP_ERROR_CHECK(error_code) \
	do { \
		if (error_code != 0) { \
			printf("Error: %d\n", error_code); \
			while (1) \
				; \
		} \
	} while (0)

static bool led_state;

static struct k_delayed_work tick;
static bool tick_fired;

/** Transport handle used for data exchange, obtained on @coap_init. */
static coap_transport_handle_t *transport4_handle;

/** Transport handle used for data exchange, obtained on @coap_init. */
static coap_transport_handle_t *transport6_handle;

static u8_t well_known_core[100];
static const char lights_name[] = "lights";
static const char led3_name[] = "led3";
static coap_resource_t led3;
static u32_t observer_sequence_num;

static struct pollfd fds[4];
static int nfds;

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

/**@brief Function to provision credentials used
 *        for secure transport by the CoAP client.
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

/**@brief Method to get the current value of resource led3 in requested
 *        content type.
 */
static void app_coap_led3_value_get(coap_content_type_t content_type,
				    char **str)
{
	if (content_type == COAP_CT_APP_JSON) {
		static char response_str_true[15] = { "{\"led3\": True}\0" };
		static char response_str_false[16] = { "{\"led3\": False}\0" };

		if ((bool)LED_IS_ON(LED_THREE) == true) {
			*str = response_str_true;
		} else {
			*str = response_str_false;
		}
	} else   {
		/* Use plain text for all other content types. */
		static char response_str[2];

		memset(response_str, '\0', sizeof(response_str));
		sprintf(response_str, "%d", (bool)LED_IS_ON(LED_THREE));
		*str = response_str;
	}
}


static void app_subscriber_response_handle(u32_t status, void *arg,
					   coap_message_t *response)
{
	u32_t err_code;

	switch (status) {
	case ECONNRESET:
	{
	}
	/* no break */
	case ETIMEDOUT:
	{
		coap_observer_t *observer = (coap_observer_t *)arg;

		/* Remove observer from its list. */
		u32_t handle;

		err_code = coap_observe_server_search(
				&handle, observer->p_remote,
				observer->p_resource_of_interest);
		APP_ERROR_CHECK(err_code);

		err_code = coap_observe_server_unregister(handle);
		APP_ERROR_CHECK(err_code);
	}
	break;

	default:
	{
		/* The CON message went find. */
	}
	break;
	}
}


/**@brief Method to notify all subscribers of the resource LED3. */
static void app_led3_subscriber_notify(coap_msg_type_t type)
{
	/* Fetch all observers which are subscribed to this resource.
	 * Then send an update value too each observer.
	 */
	coap_observer_t *observer = NULL;
	u32_t err_code;

	while (coap_observe_server_next_get(&observer, observer, &led3) == 0) {
		/* Generate a message. */
		coap_message_conf_t response_config;

		memset(&response_config, 0x00, sizeof(coap_message_conf_t));

		response_config.type = type;
		response_config.code = COAP_CODE_205_CONTENT;
		response_config.response_callback =
						app_subscriber_response_handle;

		/* Copy token. */
		memcpy(&response_config.token[0], &observer->token[0],
		       observer->token_len);
		/* Copy token length. */
		response_config.token_len = observer->token_len;

		/* Set local port number to use. */
		if (observer->p_remote->sa_family == AF_INET6) {
			response_config.p_transport = transport6_handle;
		} else   {
			response_config.p_transport = transport4_handle;
		}

		coap_message_t *response;

		err_code = coap_message_new(&response, &response_config);
		APP_ERROR_CHECK(err_code);

		/* Set custom misc. argument. */
		response->p_arg = observer;

		err_code = coap_message_remote_addr_set(response,
							observer->p_remote);
		APP_ERROR_CHECK(err_code);

		err_code = coap_message_opt_uint_add(response,
						     COAP_OPT_OBSERVE,
						     observer_sequence_num++);
		APP_ERROR_CHECK(err_code);

		err_code = coap_message_opt_uint_add(response,
						     COAP_OPT_MAX_AGE,
						     led3.expire_time);
		APP_ERROR_CHECK(err_code);

		char *response_str;

		app_coap_led3_value_get(observer->ct, &response_str);
		err_code = coap_message_payload_set(response, response_str,
						    strlen(response_str));
		APP_ERROR_CHECK(err_code);

		u32_t msg_handle;

		err_code = coap_message_send(&msg_handle, response);
		APP_ERROR_CHECK(err_code);

		err_code = coap_message_delete(response);
		APP_ERROR_CHECK(err_code);
	}
}



/**@brief Handle request on the resource LED3. */
static void app_led3_request_handle(coap_resource_t *resource,
				    coap_message_t *request)
{
	coap_message_conf_t response_config;
	u32_t err_code;

	memset(&response_config, 0x00, sizeof(coap_message_conf_t));

	printf("LED3 request\n");

	if (request->header.type == COAP_TYPE_NON) {
		response_config.type = COAP_TYPE_NON;
	} else if (request->header.type == COAP_TYPE_CON) {
		response_config.type = COAP_TYPE_ACK;
	}

	/* PIGGY BACKED RESPONSE */
	response_config.code = COAP_CODE_405_METHOD_NOT_ALLOWED;
	/* Copy message ID. */
	response_config.id = request->header.id;
	/* Set local transport to be used to send the response.
	 * Here, same as the one received in the request.
	 */
	response_config.p_transport = request->p_transport;
	/* Copy token. */
	memcpy(&response_config.token[0], &request->token[0],
	       request->header.token_len);
	/* Copy token length. */
	response_config.token_len = request->header.token_len;

	coap_message_t *response;

	err_code = coap_message_new(&response, &response_config);
	APP_ERROR_CHECK(err_code);

	err_code = coap_message_remote_addr_set(response, request->p_remote);
	APP_ERROR_CHECK(err_code);

	/* Handle request. */
	switch (request->header.code) {
	case COAP_CODE_GET:
	{
		response->header.code = COAP_CODE_205_CONTENT;

		/* Select the first common content type between the resource
		 * and the CoAP client.
		 */
		coap_content_type_t ct_to_use;

		err_code = coap_message_ct_match_select(&ct_to_use, request,
							resource);
		if (err_code != 0) {
			/* None of the accepted content formats are supported
			 * in this resource endpoint.
			 */
			response->header.code =
				COAP_CODE_415_UNSUPPORTED_CONTENT_FORMAT;
			response->header.type = COAP_TYPE_RST;

			break;
		}

		if (coap_message_opt_present(request, COAP_OPT_OBSERVE) == 0) {
			/* Locate the option and check the value. */
			u32_t observe_option = 0;

			for (int i = 0; i < request->options_count; i++) {
				if (request->options[i].number ==
							COAP_OPT_OBSERVE) {
					err_code = coap_opt_uint_decode(
						&observe_option,
						request->options[i].length,
						request->options[i].p_data);
					if (err_code != 0) {
						APP_ERROR_CHECK(err_code);
					}
					break;
				}
			}

			if (observe_option == 0) {
				/* Register observer, and if successful,
				 * add the Observe option in the reply.
				 */
				u32_t handle;
				coap_observer_t observer;

				/* Set the token length. */
				observer.token_len = request->header.token_len;
				/* Set the resource of interest. */
				observer.p_resource_of_interest = resource;
				/* Set the remote. */
				observer.p_remote = request->p_remote;
				/* Set the token. */
				memcpy(observer.token, request->token,
				       observer.token_len);

				/* Set the content format to be used for
				 * subsequent notifications.
				 */
				observer.ct = ct_to_use;

				err_code = coap_observe_server_register(
							&handle, &observer);
				if (err_code == 0) {
					err_code = coap_message_opt_uint_add(
						response,
						COAP_OPT_OBSERVE,
						observer_sequence_num++);
					APP_ERROR_CHECK(err_code);

					err_code = coap_message_opt_uint_add(
						response, COAP_OPT_MAX_AGE,
						resource->expire_time);
					APP_ERROR_CHECK(err_code);
				}
				/* If the registration of the observer could not
				 * be done, handle this as a normal message.
				 */
			} else   {
				u32_t handle;

				err_code = coap_observe_server_search(
						&handle, request->p_remote,
						resource);
				if (err_code == 0) {
					err_code =
						coap_observe_server_unregister(
								handle);
					APP_ERROR_CHECK(err_code);
				}
			}
		}

		/* Set response payload to the actual LED state. */
		char *response_str;

		app_coap_led3_value_get(ct_to_use, &response_str);
		err_code = coap_message_payload_set(response, response_str,
						    strlen(response_str));
		APP_ERROR_CHECK(err_code);

		break;
	}

	case COAP_CODE_PUT:
	{
		response->header.code = COAP_CODE_204_CHANGED;

		/* Change LED state according to request. */
		switch (request->p_payload[0]) {
		case APP_COMMAND_ON:
		{
			LEDS_ON(LED_THREE);
			break;
		}
		case APP_COMMAND_OFF:
		{
			LEDS_OFF(LED_THREE);
			break;
		}
		case APP_COMMAND_TOGGLE:
		{
			LEDS_INVERT(LED_THREE);
			break;
		}
		default:
		{
			response->header.code = COAP_CODE_400_BAD_REQUEST;
			break;
		}
		}
		break;
	}

	default:
	{
		response->header.code = COAP_CODE_405_METHOD_NOT_ALLOWED;
		break;
	}
	}

	u32_t msg_handle;

	err_code = coap_message_send(&msg_handle, response);
	APP_ERROR_CHECK(err_code);

	err_code = coap_message_delete(response);
	APP_ERROR_CHECK(err_code);

	if (request->header.code == COAP_CODE_PUT) {
		app_led3_subscriber_notify(COAP_TYPE_NON);
	}
}


/**@brief Function for catering CoAP module with periodic time ticks. */
static void app_coap_time_tick(struct k_work *work)
{
	ARG_UNUSED(work);

	tick_fired = true;

	k_delayed_work_submit(&tick, K_MSEC(APP_COAP_TICK_INTERVAL_MS));
}

static void tick_handler(void)
{
	static u32_t msg_count;

	/* Pass a tick to CoAP in order to re-transmit any pending messages. */
	(void)coap_time_tick();

	if (led3.expire_time <= (0 + OBSERVE_NOTIFY_DELTA_MAX_AGE)) {
		led3.expire_time = led3.max_age;

		/* Notify observers if any. */
		if (msg_count == 4) {
			app_led3_subscriber_notify(COAP_TYPE_CON);
			msg_count = 0;
		} else   {
			app_led3_subscriber_notify(COAP_TYPE_NON);
		}

		msg_count++;
	} else   {
		/* Update the expire time for LED3 observable resource. */
		led3.expire_time--;
	}
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


/**@brief Handle resource discovery request from the client. */
void app_well_known_core_request_handle(coap_resource_t *resource,
					coap_message_t *request)
{
	coap_message_conf_t response_config;
	u32_t err_code;

	memset(&response_config, 0x00, sizeof(coap_message_conf_t));

	printf("Coap Well known request\n");

	if (request->header.type == COAP_TYPE_NON) {
		response_config.type = COAP_TYPE_NON;
	} else if (request->header.type == COAP_TYPE_CON) {
		response_config.type = COAP_TYPE_ACK;
	}

	/* PIGGY BACKED RESPONSE */
	response_config.code = COAP_CODE_205_CONTENT;
	/* Copy message ID. */
	response_config.id = request->header.id;
	/* Set local transport to be used to send the response.
	 * Here, same as the one received in the request.
	 */
	response_config.p_transport = request->p_transport;
	/* Copy token. */
	memcpy(&response_config.token[0], &request->token[0],
	       request->header.token_len);
	/* Copy token length. */
	response_config.token_len = request->header.token_len;

	coap_message_t *response;

	err_code = coap_message_new(&response, &response_config);
	APP_ERROR_CHECK(err_code);

	err_code = coap_message_remote_addr_set(response, request->p_remote);
	APP_ERROR_CHECK(err_code);

	response->p_remote = request->p_remote;

	err_code = coap_message_opt_uint_add(response, COAP_OPT_CONTENT_FORMAT,
					     COAP_CT_APP_LINK_FORMAT);
	APP_ERROR_CHECK(err_code);

	err_code = coap_message_payload_set(response, well_known_core,
					    strlen((char *)well_known_core));
	APP_ERROR_CHECK(err_code);

	u32_t msg_handle;

	err_code = coap_message_send(&msg_handle, response);
	APP_ERROR_CHECK(err_code);

	err_code = coap_message_delete(response);
	APP_ERROR_CHECK(err_code);
}


/**@brief Setup the resources on the application as a CoAP server. */
static void app_coap_resource_setup(void)
{
	u32_t err_code;

	static coap_resource_t root;
	static coap_resource_t well_known;
	static coap_resource_t core;
	static coap_resource_t lights;

	err_code = coap_resource_create(&root, "/");
	APP_ERROR_CHECK(err_code);

	err_code = coap_resource_create(&well_known, ".well-known");
	APP_ERROR_CHECK(err_code);
	err_code = coap_resource_child_add(&root, &well_known);
	APP_ERROR_CHECK(err_code);

	err_code = coap_resource_create(&core, "core");
	APP_ERROR_CHECK(err_code);

	core.permission = COAP_PERM_GET;
	core.callback = app_well_known_core_request_handle;

	err_code = coap_resource_child_add(&well_known, &core);
	APP_ERROR_CHECK(err_code);

	err_code = coap_resource_create(&lights, lights_name);
	APP_ERROR_CHECK(err_code);

	err_code = coap_resource_child_add(&root, &lights);
	APP_ERROR_CHECK(err_code);

	err_code = coap_resource_create(&led3, led3_name);
	APP_ERROR_CHECK(err_code);

	led3.permission = (COAP_PERM_GET | COAP_PERM_PUT | COAP_PERM_OBSERVE);
	led3.callback = app_led3_request_handle;
	led3.ct_support_mask = COAP_CT_MASK_APP_JSON | COAP_CT_MASK_PLAIN_TEXT;
	led3.max_age = 15;

	err_code = coap_resource_child_add(&lights, &led3);
	APP_ERROR_CHECK(err_code);

	u16_t size = sizeof(well_known_core);

	err_code = coap_resource_well_known_generate(well_known_core, &size);
	APP_ERROR_CHECK(err_code);
}


/**@brief Handles an errors notified by CoAP. */
static void app_coap_error_handler(u32_t error_code, coap_message_t *message)
{
	/* If any response fill the response with a appropriate response
	 * message.
	 */
	printf("CoAP error handler: error_code: %d\n", (int)error_code);
}


/**@brief Initialize CoAP. */
static void app_coap_init(void)
{
	struct sockaddr_in6 server6_addr;
	struct sockaddr_in server_addr;
	struct sockaddr_in6 secure_server6_addr;
	struct sockaddr_in secure_server_addr;

	memset(&server6_addr, 0, sizeof(struct sockaddr_in6));
	server6_addr.sin6_port = htons(APP_COAP_LOCAL_SERVER_PORT);
	server6_addr.sin6_family = AF_INET6;

	memset(&server_addr, 0, sizeof(struct sockaddr_in));
	server_addr.sin_port = htons(APP_COAP_LOCAL_SERVER_PORT);
	server_addr.sin_family = AF_INET;

	memset(&secure_server6_addr, 0, sizeof(struct sockaddr_in6));
	secure_server6_addr.sin6_port = htons(
					APP_COAP_LOCAL_SECURE_SERVER_PORT);
	secure_server6_addr.sin6_family = AF_INET6;

	memset(&secure_server_addr, 0, sizeof(struct sockaddr_in));
	secure_server_addr.sin_port = htons(APP_COAP_LOCAL_SECURE_SERVER_PORT);
	secure_server_addr.sin_family = AF_INET;


	sec_tag_t sec_tag_list[] = { APP_COAP_SEC_TAG };

	coap_sec_config_t setting = {
		.role = 1, /* 1 -> Server role */
		.sec_tag_count = ARRAY_SIZE(sec_tag_list),
		.p_sec_tag_list = sec_tag_list
	};

	coap_local_t local_port_list[COAP_PORT_COUNT] = {
		{
			.p_addr = (struct sockaddr *)&server6_addr,
			.p_setting = NULL,
			.protocol = IPPROTO_UDP
		},
		{
			.p_addr = (struct sockaddr *)&server_addr,
			.p_setting = NULL,
			.protocol = IPPROTO_UDP
		},
		{
			.p_addr = (struct sockaddr *)&secure_server6_addr,
			.p_setting =  &setting,
			.protocol = IPPROTO_DTLS_1_2
		},
		{
			.p_addr = (struct sockaddr *)&secure_server_addr,
			.p_setting =  &setting,
			.protocol = IPPROTO_DTLS_1_2
		}
	};

	coap_transport_init_t port_list;

	port_list.p_port_table = &local_port_list[0];

	int err_code = coap_init(245121, &port_list, k_malloc, k_free);

	if (err_code != 0) {
		printf("Failed to initialize CoAP\n");
		return;
	}

	transport6_handle = local_port_list[0].p_transport;
	transport4_handle = local_port_list[1].p_transport;

	/* TODO VERY dirty hack, need a better way to get socket fd. */
	fds[nfds].fd = *(int *)local_port_list[0].p_transport;
	fds[nfds].events = POLLIN;
	nfds++;
	fds[nfds].fd = *(int *)local_port_list[1].p_transport;
	fds[nfds].events = POLLIN;
	nfds++;
	fds[nfds].fd = *(int *)local_port_list[2].p_transport;
	fds[nfds].events = POLLIN;
	nfds++;
	fds[nfds].fd = *(int *)local_port_list[3].p_transport;
	fds[nfds].events = POLLIN;
	nfds++;

	err_code = coap_error_handler_register(app_coap_error_handler);
	if (err_code != 0) {
		printf("Failed to register CoAP error handler\n");
		APP_ERROR_CHECK(err_code);
	}

	app_coap_resource_setup();
}

static void tls_init(void)
{
	int err_code = tls_credential_add(APP_COAP_SEC_TAG,
					  TLS_CREDENTIAL_PSK,
					  APP_COAP_SEC_PSK,
					  sizeof(APP_COAP_SEC_PSK));
	if (err_code < 0) {
		printf("Failed to register PSK: %d\n", err_code);
	}

	err_code = tls_credential_add(APP_COAP_SEC_TAG,
				      TLS_CREDENTIAL_PSK_ID,
				      APP_COAP_SEC_IDENTITY,
				      sizeof(APP_COAP_SEC_IDENTITY));
	if (err_code < 0) {
		printf("Failed to register PSK ID: %d\n", err_code);
	}
}

/**@brief Function for application main entry. */
int main(void)
{
	printf("CoAP application start\n");

	k_delayed_work_init(&tick, app_coap_time_tick);

	tls_init();
	app_coap_init();

	k_delayed_work_submit(&tick, K_MSEC(APP_COAP_TICK_INTERVAL_MS));

	/* Enter main loop. */
	while (true) {
		app_process();
	}
}
