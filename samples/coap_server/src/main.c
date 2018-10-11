/*$$$LICENCE_NORDIC_STANDARD<2018>$$$*/
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <coap_api.h>

#if 0
#include "sys/socket.h"
#include "bsd.h"
#include "app_timer.h"
#include "app_util_platform.h"
#include "app_error.h"
#include "nrf.h"
#include "nrf_error.h"
#include "boards.h"
#include "iot_timer.h"
#include "nrf_delay.h"
#include "iot_errors.h"
#include "coap_observe_api.h"
#include "app_mem_manager.h"


#define APP_COAP_LOCAL_SERVER_PORT          5683                                                   /**< Local server port on which the CoAP server expects the remote clients to communicate. */
#define APP_COAP_LOCAL_SECURE_SERVER_PORT   5684                                                   /**< Local secure server port on which the CoAP server expects the remote clients to communicate. */

#define APP_COAP_SEC_TAG                    2018                                                   /**< Tag used to identify security credentials used by the client. */
#define APP_COAP_SEC_PSK                    "73656372657450534b30"                                 /**< Pre-shared key used for DTLS in hex format. */
#define APP_COAP_SEC_IDENTITY               "Client_identity"                                      /**< Client identity used for DTLS. */

#define OBSERVE_NOTIFY_DELTA_MAX_AGE        2                                                      /**< Number of seconds prior to a max-age timeout which an updated state of the observed value should be sent to the observers. */
#define APP_COAP_TICK_INTERVAL_MS           1000                                                   /**< Interval between periodic callbacks to CoAP module. */

#define COMMAND_OFF                         '0'
#define COMMAND_ON                          '1'
#define COMMAND_TOGGLE                      '2'

#define LED_ONE                             BSP_LED_0_MASK                                         /**< Blinking LED. */
#define LED_THREE                           BSP_LED_2_MASK                                         /**< CoAP LED resource. */

/* Buffers per port of CoAP. */
#define APP_COAP_BUFFER_COUNT_PER_PORT      2                                                      /**< Number of buffers needed per port - one for RX and one for TX */
#define APP_COAP_MEM_POOL_COUNT             1                                                      /**< Number of memory pools used. */

#define APP_COAP_BUFFER_PER_PORT            (COAP_MESSAGE_DATA_MAX_SIZE * \
                                            APP_COAP_BUFFER_COUNT_PER_PORT)
#define APP_COAP_MAX_BUFFER_SIZE            (APP_COAP_BUFFER_PER_PORT * COAP_PORT_COUNT)           /**< Maximum memory buffer used for memory allocator for CoAP */

#define APP_MAX_AT_READ_LENGTH              100
#define APP_MAX_AT_WRITE_LENGTH             100

static uint8_t  m_app_coap_data_buffer[APP_COAP_MAX_BUFFER_SIZE];                                  /**< Buffer contributed by CoAP for its use. */


/**< Pool submitted to the memory management.*/
static const nrf_mem_pool_t m_app_coap_pool[APP_COAP_MEM_POOL_COUNT] =
{
    {
        .size  = COAP_MESSAGE_DATA_MAX_SIZE,
        .count = (APP_COAP_BUFFER_COUNT_PER_PORT * COAP_PORT_COUNT)
    }
};

/**< Configuration used for memory contribution. */
static const nrf_mem_desc_t app_coap_mem_desc =
{
    .mem_type       = NRF_MEM_TYPE_DEFAULT,
    .policy         = NRF_MEM_POLICY_DEFAULT,
    .p_memory       = (uint8_t *)m_app_coap_data_buffer,
    .memory_size    = APP_COAP_MAX_BUFFER_SIZE,
    .pool_list_size = APP_COAP_MEM_POOL_COUNT,
    .p_pool_list    = (nrf_mem_pool_t *)m_app_coap_pool
};


APP_TIMER_DEF(m_iot_timer_tick_src_id);
static coap_transport_handle_t * mp_transport4_handle;                                             /**< Transport handle used for data exchange, obtained on @coap_init. */
static coap_transport_handle_t * mp_transport6_handle;                                             /**< Transport handle used for data exchange, obtained on @coap_init. */
static uint8_t                m_well_known_core[100];

static const char             m_lights_name[] = "lights";
static const char             m_led3_name[]   = "led3";

static coap_resource_t        m_led3;
static uint32_t               m_observer_sequence_num = 0;


/**@brief Handle application errors. */
void app_error_fault_handler(uint32_t id, uint32_t pc, uint32_t info)
{
    NRF_BREAKPOINT_COND;
    // On assert, the system can only recover with a reset.

    app_error_save_and_stop(id, pc, info);
}


/**@brief Recoverable BSD library error. */
void bsd_recoverable_error_handler(uint32_t error)
{
    UNUSED_VARIABLE(error);

    while (true)
    {
        ;
    }
}


/**@brief Irrecoverable BSD library error. */
void bsd_irrecoverable_error_handler(uint32_t error)
{
    UNUSED_VARIABLE(error);

    while (true)
    {
        ;
    }
}


static void app_modem_configure(void)
{
    int at_socket_fd  = -1;
    int bytes_written = 0;
    int bytes_read    = 0;

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

    while (true)
    {
        bytes_read = read(at_socket_fd, read_buffer, APP_MAX_AT_READ_LENGTH);

        if ((strncmp("+CEREG: 1", read_buffer, 9) == 0) ||
            (strncmp("+CEREG:1", read_buffer, 8) == 0))
        {
            break;
        }
    }
    UNUSED_RETURN_VALUE(close(at_socket_fd));
}


/**@brief Function to provision credentials used for secure transport by the CoAP client. */
static void app_provision(void)
{
    int at_socket_fd  = -1;
    int bytes_written = 0;
    int bytes_read    = 0;

    char write_buffer[APP_MAX_AT_WRITE_LENGTH];
    char read_buffer[APP_MAX_AT_READ_LENGTH];

    at_socket_fd = socket(AF_LTE, 0, NPROTO_AT);
    APP_ERROR_CHECK_BOOL(at_socket_fd >= 0);

    #define WRITE_OPCODE  0
    #define IDENTITY_CODE 4
    #define PSK_CODE      3

    memset (write_buffer, 0, APP_MAX_AT_WRITE_LENGTH);
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

    memset (write_buffer, 0, APP_MAX_AT_WRITE_LENGTH);
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


/**@brief Method to get the current value of resource led3 in requested content type. */
static void app_coap_led3_value_get(coap_content_type_t content_type, char ** str)
{
    if (content_type == COAP_CT_APP_JSON)
    {
        static char response_str_true[15]  = {"{\"led3\": True}\0"};
        static char response_str_false[16] = {"{\"led3\": False}\0"};

        if ((bool)LED_IS_ON(LED_THREE) == true)
        {
            *str = response_str_true;
        }
        else
        {
            *str = response_str_false;
        }
    }
    else
    {
        // Use plain text for all other content types.
        static char response_str[2];
        memset(response_str, '\0', sizeof(response_str));
        sprintf(response_str, "%d", (bool)LED_IS_ON(LED_THREE));
        *str = response_str;
    }
}


static void app_subscriber_response_handle(uint32_t status, void * arg, coap_message_t * p_response)
{
    uint32_t err_code;
    switch (status)
    {
        case COAP_TRANSMISSION_RESET_BY_PEER:
        {
        }
        /* no break */
        case COAP_TRANSMISSION_TIMEOUT:
        {
            coap_observer_t * p_observer = (coap_observer_t *)arg;

            // Remove observer from its list.
            uint32_t handle;
            err_code = coap_observe_server_search(&handle, p_observer->p_remote, p_observer->p_resource_of_interest);
            APP_ERROR_CHECK(err_code);

            err_code = coap_observe_server_unregister(handle);
            APP_ERROR_CHECK(err_code);
        }
        break;

        default:
        {
            // The CON message went find.
        }
        break;
    }
}


/**@brief Method to notify all subscribers of the resource LED3. */
static void app_led3_subscriber_notify(coap_msg_type_t type)
{
    // Fetch all observers which are subscribed to this resource.
    // Then send an update value too each observer.
    coap_observer_t * p_observer = NULL;
    while (coap_observe_server_next_get(&p_observer, p_observer, &m_led3) == NRF_SUCCESS)
    {
        // Generate a message.
        coap_message_conf_t response_config;
        memset(&response_config, 0x00, sizeof(coap_message_conf_t));

        response_config.type              = type;
        response_config.code              = COAP_CODE_205_CONTENT;
        response_config.response_callback = app_subscriber_response_handle;

        // Copy token.
        memcpy(&response_config.token[0], &p_observer->token[0], p_observer->token_len);
        // Copy token length.
        response_config.token_len = p_observer->token_len;

        // Set local port number to use.
        if (p_observer->p_remote->sa_family == AF_INET6)
        {
            response_config.p_transport = mp_transport6_handle;
        }
        else
        {
            response_config.p_transport = mp_transport4_handle;
        }

        coap_message_t * p_response;
        uint32_t err_code = coap_message_new(&p_response, &response_config);
        APP_ERROR_CHECK(err_code);

        // Set custom misc. argument.
        p_response->p_arg = p_observer;

        err_code = coap_message_remote_addr_set(p_response, p_observer->p_remote);
        APP_ERROR_CHECK(err_code);

        err_code = coap_message_opt_uint_add(p_response, COAP_OPT_OBSERVE, m_observer_sequence_num++);
        APP_ERROR_CHECK(err_code);

        err_code = coap_message_opt_uint_add(p_response, COAP_OPT_MAX_AGE, m_led3.expire_time);
        APP_ERROR_CHECK(err_code);

        char * response_str;
        app_coap_led3_value_get(p_observer->ct, &response_str);
        err_code = coap_message_payload_set(p_response, response_str, strlen(response_str));
        APP_ERROR_CHECK(err_code);

        uint32_t msg_handle;
        err_code = coap_message_send(&msg_handle, p_response);
        APP_ERROR_CHECK(err_code);

        err_code = coap_message_delete(p_response);
        APP_ERROR_CHECK(err_code);
    }
}


/**@brief Handle request on the resource LED3. */
static void app_led3_request_handle(coap_resource_t * p_resource, coap_message_t * p_request)
{
    coap_message_conf_t response_config;
    memset(&response_config, 0x00, sizeof(coap_message_conf_t));

    if (p_request->header.type == COAP_TYPE_NON)
    {
        response_config.type = COAP_TYPE_NON;
    }
    else if (p_request->header.type == COAP_TYPE_CON)
    {
        response_config.type = COAP_TYPE_ACK;
    }

    // PIGGY BACKED RESPONSE
    response_config.code = COAP_CODE_405_METHOD_NOT_ALLOWED;
    // Copy message ID.
    response_config.id = p_request->header.id;
    // Set local transport to be used to send the response.
    // Here, same as the one received in the request.
    response_config.p_transport = p_request->p_transport;
    // Copy token.
    memcpy(&response_config.token[0], &p_request->token[0], p_request->header.token_len);
    // Copy token length.
    response_config.token_len = p_request->header.token_len;

    coap_message_t * p_response;
    uint32_t err_code = coap_message_new(&p_response, &response_config);
    APP_ERROR_CHECK(err_code);

    err_code = coap_message_remote_addr_set(p_response, p_request->p_remote);
    APP_ERROR_CHECK(err_code);

    // Handle request.
    switch (p_request->header.code)
    {
        case COAP_CODE_GET:
        {
            p_response->header.code = COAP_CODE_205_CONTENT;

            // Select the first common content type between the resource and the CoAP client.
            coap_content_type_t ct_to_use;
            err_code = coap_message_ct_match_select(&ct_to_use, p_request, p_resource);
            if (err_code != NRF_SUCCESS)
            {
                // None of the accepted content formats are supported in this resource endpoint.
                p_response->header.code = COAP_CODE_415_UNSUPPORTED_CONTENT_FORMAT;
                p_response->header.type = COAP_TYPE_RST;
            }
            else
            {
                if (coap_message_opt_present(p_request, COAP_OPT_OBSERVE) == NRF_SUCCESS)
                {
                    // Locate the option and check the value.
                    uint32_t observe_option = 0;

                    uint8_t index;
                    for (index = 0; index < p_request->options_count; index++)
                    {
                        if (p_request->options[index].number == COAP_OPT_OBSERVE)
                        {
                            err_code = coap_opt_uint_decode(&observe_option,
                                                            p_request->options[index].length,
                                                            p_request->options[index].p_data);
                            if (err_code != NRF_SUCCESS)
                            {
                               APP_ERROR_CHECK(err_code);
                            }
                            break;
                        }
                    }

                    if (observe_option == 0)
                    {
                        // Register observer, and if successful, add the Observe option in the reply.
                        uint32_t handle;
                        coap_observer_t observer;

                        // Set the token length.
                        observer.token_len              = p_request->header.token_len;
                        // Set the resource of interest.
                        observer.p_resource_of_interest = p_resource;
                        // Set the remote.
                        observer.p_remote               = p_request->p_remote;
                        // Set the token.
                        memcpy(observer.token, p_request->token, observer.token_len);

                        // Set the content format to be used for subsequent notifications.
                        observer.ct = ct_to_use;

                        err_code = coap_observe_server_register(&handle, &observer);
                        if (err_code == NRF_SUCCESS)
                        {
                            err_code = coap_message_opt_uint_add(p_response, COAP_OPT_OBSERVE, m_observer_sequence_num++);
                            APP_ERROR_CHECK(err_code);

                            err_code = coap_message_opt_uint_add(p_response, COAP_OPT_MAX_AGE, p_resource->expire_time);
                            APP_ERROR_CHECK(err_code);
                        }
                        // If the registration of the observer could not be done, handle this as a normal message.
                    }
                    else
                    {
                        uint32_t handle;
                        err_code = coap_observe_server_search(&handle, p_request->p_remote, p_resource);
                        if (err_code == NRF_SUCCESS)
                        {
                            err_code = coap_observe_server_unregister(handle);
                            APP_ERROR_CHECK(err_code);
                        }
                    }
                }

                // Set response payload to the actual LED state.
                char * response_str;
                app_coap_led3_value_get(ct_to_use, &response_str);
                err_code = coap_message_payload_set(p_response, response_str, strlen(response_str));
                APP_ERROR_CHECK(err_code);
            }
            break;
        }

        case COAP_CODE_PUT:
        {
            p_response->header.code = COAP_CODE_204_CHANGED;

            // Change LED state according to request.
            switch (p_request->p_payload[0])
            {
                case COMMAND_ON:
                {
                    LEDS_ON(LED_THREE);
                    break;
                }
                case COMMAND_OFF:
                {
                    LEDS_OFF(LED_THREE);
                    break;
                }
                case COMMAND_TOGGLE:
                {
                    LEDS_INVERT(LED_THREE);
                    break;
                }
                default:
                {
                    p_response->header.code = COAP_CODE_400_BAD_REQUEST;
                    break;
                }
            }
            break;
        }

        default:
        {
            p_response->header.code = COAP_CODE_405_METHOD_NOT_ALLOWED;
            break;
        }
    }

    uint32_t msg_handle;
    err_code = coap_message_send(&msg_handle, p_response);
    APP_ERROR_CHECK(err_code);

    err_code = coap_message_delete(p_response);
    APP_ERROR_CHECK(err_code);

    if (p_request->header.code == COAP_CODE_PUT)
    {
        app_led3_subscriber_notify(COAP_TYPE_NON);
    }
}


/**@brief Update the wall clock of the IoT Timer module. */
static void iot_timer_tick_callback(void * p_context)
{
    UNUSED_VARIABLE(p_context);

    ret_code_t err_code = iot_timer_update();
    APP_ERROR_CHECK(err_code);
}


/**@brief Function for catering CoAP module with periodic time ticks. */
static void app_coap_time_tick(iot_timer_time_in_ms_t wall_clock_value)
{
    // Pass a tick to CoAP in order to re-transmit any pending messages.
    UNUSED_RETURN_VALUE(coap_time_tick());

    if (m_led3.expire_time <= (0 + OBSERVE_NOTIFY_DELTA_MAX_AGE))
    {
        m_led3.expire_time = m_led3.max_age;

        static uint32_t msg_count = 0;

        // Notify observers if any.
        if (msg_count == 4)
        {
            app_led3_subscriber_notify(COAP_TYPE_CON);
            msg_count = 0;
        }
        else
        {
            app_led3_subscriber_notify(COAP_TYPE_NON);
        }

        msg_count++;
    }
    else
    {
        // Update the expire time for LED3 observable resource.
        m_led3.expire_time--;
    }
}


/**@brief Timer module initialization. */
static void timers_init(void)
{
    ret_code_t err_code;

    // Initialize timer module.
    APP_ERROR_CHECK(app_timer_init());

    // Create a sys timer.
    err_code = app_timer_create(&m_iot_timer_tick_src_id,
                                APP_TIMER_MODE_REPEATED,
                                iot_timer_tick_callback);
    APP_ERROR_CHECK(err_code);
}


/**@brief Initialize the IoT Timer for CoAP tick and notifications. */
static void iot_timer_init(void)
{
    ret_code_t err_code;

    static const iot_timer_client_t list_of_clients[] =
    {
        {app_coap_time_tick, APP_COAP_TICK_INTERVAL_MS},
    };

    // The list of IoT Timer clients is declared as a constant.
    static const iot_timer_clients_list_t iot_timer_clients =
    {
        ARRAY_SIZE(list_of_clients), list_of_clients,
    };

    // Passing the list of clients to the IoT Timer module.
    err_code = iot_timer_client_list_set(&iot_timer_clients);
    APP_ERROR_CHECK(err_code);

    // Starting the app timer instance that is the tick source for the IoT Timer.
    err_code = app_timer_start(m_iot_timer_tick_src_id,
                               APP_TIMER_TICKS(IOT_TIMER_RESOLUTION_IN_MS),
                               NULL);
    APP_ERROR_CHECK(err_code);
}


/**@brief Method to service the application process. */
static void app_process(void)
{
    coap_transport_input();
}


/**@brief Handle resource discovery request from the client. */
void app_well_known_core_request_handle(coap_resource_t * p_resource, coap_message_t * p_request)
{
    coap_message_conf_t response_config;
    memset(&response_config, 0x00, sizeof(coap_message_conf_t));

    if (p_request->header.type == COAP_TYPE_NON)
    {
        response_config.type = COAP_TYPE_NON;
    }
    else if (p_request->header.type == COAP_TYPE_CON)
    {
        response_config.type = COAP_TYPE_ACK;
    }

    // PIGGY BACKED RESPONSE
    response_config.code = COAP_CODE_205_CONTENT;
    // Copy message ID.
    response_config.id = p_request->header.id;
    // Set local transport to be used to send the response.
    // Here, same as the one received in the request.
    response_config.p_transport = p_request->p_transport;
    // Copy token.
    memcpy(&response_config.token[0], &p_request->token[0], p_request->header.token_len);
    // Copy token length.
    response_config.token_len = p_request->header.token_len;

    coap_message_t * p_response;
    uint32_t err_code = coap_message_new(&p_response, &response_config);
    APP_ERROR_CHECK(err_code);

    err_code = coap_message_remote_addr_set(p_response, p_request->p_remote);
    APP_ERROR_CHECK(err_code);

    p_response->p_remote = p_request->p_remote;

    err_code = coap_message_opt_uint_add(p_response, COAP_OPT_CONTENT_FORMAT,
                                         COAP_CT_APP_LINK_FORMAT);
    APP_ERROR_CHECK(err_code);

    err_code = coap_message_payload_set(p_response, m_well_known_core,
                                        strlen((char *)m_well_known_core));
    APP_ERROR_CHECK(err_code);

    uint32_t msg_handle;
    err_code = coap_message_send(&msg_handle, p_response);
    APP_ERROR_CHECK(err_code);

    err_code = coap_message_delete(p_response);
    APP_ERROR_CHECK(err_code);
}


/**@brief Setup the resources on the application as a CoAP server. */
static void app_coap_resource_setup(void)
{
    uint32_t err_code;

    static coap_resource_t root;
    err_code = coap_resource_create(&root, "/");
    APP_ERROR_CHECK(err_code);

    static coap_resource_t well_known;
    err_code = coap_resource_create(&well_known, ".well-known");
    APP_ERROR_CHECK(err_code);
    err_code = coap_resource_child_add(&root, &well_known);
    APP_ERROR_CHECK(err_code);

    static coap_resource_t core;
    err_code = coap_resource_create(&core, "core");
    APP_ERROR_CHECK(err_code);

    core.permission = COAP_PERM_GET;
    core.callback   = app_well_known_core_request_handle;

    err_code = coap_resource_child_add(&well_known, &core);
    APP_ERROR_CHECK(err_code);

    static coap_resource_t lights;
    err_code = coap_resource_create(&lights, m_lights_name);
    APP_ERROR_CHECK(err_code);

    err_code = coap_resource_child_add(&root, &lights);
    APP_ERROR_CHECK(err_code);

    err_code = coap_resource_create(&m_led3, m_led3_name);
    APP_ERROR_CHECK(err_code);

    m_led3.permission      = (COAP_PERM_GET | COAP_PERM_PUT | COAP_PERM_OBSERVE);
    m_led3.callback        = app_led3_request_handle;
    m_led3.ct_support_mask = COAP_CT_MASK_APP_JSON | COAP_CT_MASK_PLAIN_TEXT;
    m_led3.max_age         = 15;

    err_code = coap_resource_child_add(&lights, &m_led3);
    APP_ERROR_CHECK(err_code);

    uint16_t size = sizeof(m_well_known_core);
    err_code = coap_resource_well_known_generate(m_well_known_core, &size);
    APP_ERROR_CHECK(err_code);
}


/**@brief Handles an errors notified by CoAP. */
static void app_coap_error_handler(uint32_t error_code, coap_message_t * p_message)
{
    // If any response fill the p_response with a appropriate response message.
}


/**@brief Initialize CoAP. */
static void app_coap_init(void)
{
    // Contribute memory needed for CoAP.
    nrf_mem_id_t mem_pid;
    uint32_t err_code = app_nrf_mem_register(&mem_pid, &app_coap_mem_desc);
    APP_ERROR_CHECK(err_code);

    struct sockaddr_in6 server6_addr;
    memset(&server6_addr, 0, sizeof(struct sockaddr_in6));
    server6_addr.sin6_port   = HTONS(APP_COAP_LOCAL_SERVER_PORT);
    server6_addr.sin6_family = AF_INET6;
    server6_addr.sin6_len    =  sizeof(struct sockaddr_in6);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_port   = HTONS(APP_COAP_LOCAL_SERVER_PORT);
    server_addr.sin_family = AF_INET;
    server_addr.sin_len    =  sizeof(struct sockaddr_in);

    struct sockaddr_in6 secure_server6_addr;
    memset(&secure_server6_addr, 0, sizeof(struct sockaddr_in6));
    secure_server6_addr.sin6_port   = HTONS(APP_COAP_LOCAL_SECURE_SERVER_PORT);
    secure_server6_addr.sin6_family = AF_INET6;
    secure_server6_addr.sin6_len    =  sizeof(struct sockaddr_in6);

    struct sockaddr_in secure_server_addr;
    memset(&secure_server_addr, 0, sizeof(struct sockaddr_in));
    secure_server_addr.sin_port   = HTONS(APP_COAP_LOCAL_SECURE_SERVER_PORT);
    secure_server_addr.sin_family = AF_INET;
    secure_server_addr.sin_len    =  sizeof(struct sockaddr_in);

    #define SEC_TAG_COUNT 1

    nrf_sec_tag_t     sec_tag_list[SEC_TAG_COUNT] = {APP_COAP_SEC_TAG};

    nrf_sec_config_t setting =
    {
        .role           = 1,    // 1 -> Server role
        .sec_tag_count  = SEC_TAG_COUNT,
        .p_sec_tag_list = &sec_tag_list[0]
    };

    coap_local_t local_port_list[COAP_PORT_COUNT] =
    {
        {
            .p_addr    = (struct sockaddr *)&server6_addr,
            .p_setting = NULL,
            .protocol  = IPPROTO_UDP
        },
        {
            .p_addr    = (struct sockaddr *)&server_addr,
            .p_setting = NULL,
            .protocol  = IPPROTO_UDP
        },
        {
            .p_addr    = (struct sockaddr *)&secure_server6_addr,
            .p_setting =  &setting,
            .protocol  = SPROTO_DTLS1v2
        },
        {
            .p_addr = (struct sockaddr *)&secure_server_addr,
            .p_setting =  &setting,
            .protocol  = SPROTO_DTLS1v2
        }
    };

    coap_transport_init_t port_list;
    port_list.p_port_table = &local_port_list[0];

    err_code = coap_init(245121, &port_list, app_nrf_malloc, app_nrf_free);
    APP_ERROR_CHECK(err_code);

    mp_transport6_handle = local_port_list[0].p_transport;
    mp_transport4_handle = local_port_list[1].p_transport;

    err_code = coap_error_handler_register(app_coap_error_handler);
    APP_ERROR_CHECK(err_code);

    app_coap_resource_setup();
}


/**@brief Function for the LEDs initialization. */
static void leds_init(void)
{
    // Configure LEDs and set OFF.
    LEDS_CONFIGURE(LED_ONE | LED_THREE);
    LEDS_OFF(LED_ONE | LED_THREE);
}

#endif
/**@brief Function for application main entry. */
int main(void)
{
#if 0
    UNUSED_RETURN_VALUE(app_nrf_mem_init());

    bsd_init();

    app_provision();

    leds_init();

    app_modem_configure();

    timers_init();
    iot_timer_init();

    app_coap_init();
#endif
    // Enter main loop.
    while (true)
    {
#if 0
        app_process();
#endif
    }
}
