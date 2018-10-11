/*$$$LICENCE_NORDIC_STANDARD<2017>$$$*/
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <coap_api.h>

#if 0
#include "sys/socket.h"
#include "bsd.h"
#include "app_timer.h"
#include "app_error.h"
#include "nrf.h"
#include "boards.h"
#include "iot_timer.h"
#include "nrf_delay.h"
#include "coap_api.h"
#include "app_mem_manager.h"


#define APP_COAP_TICK_INTERVAL_MS           5000                                                  /**< Interval between periodic callbacks to CoAP module. */
#define APP_COAP_LOCAL_CLIENT_PORT          9685                                                  /**< Local client port which the CoAP client uses to communicate to a CoAP Server.*/
#define APP_COAP_LOCAL_SECURE_CLIENT_PORT   9785                                                  /**< Local client port which the CoAP client uses to communicate to a CoAP Secure Server.*/
#define APP_COAP_REMOTE_SERVER_PORT         5683                                                  /**< Remote CoAP server port on which client can communicate. */
#define APP_COAP_REMOTE_SECURE_SERVER_PORT  5784                                                  /**< Remote CoAP server port on which client can communicate. */

#define APP_MAX_AT_READ_LENGTH              100
#define APP_MAX_AT_WRITE_LENGTH             100
#define APP_COAP_BUFFER_COUNT_PER_PORT      2                                                      /**< Number of buffers needed per port - one for RX and one for TX */
#define APP_COAP_MEM_POOL_COUNT             1                                                      /**< Number of memory pools used. */
#define APP_COAP_BUFFER_PER_PORT            (COAP_MESSAGE_DATA_MAX_SIZE * APP_COAP_BUFFER_COUNT_PER_PORT)
#define APP_COAP_MAX_BUFFER_SIZE            (APP_COAP_BUFFER_PER_PORT * COAP_PORT_COUNT)           /**< Maximum memory buffer used for memory allocator for CoAP */

#define APP_COAP_SEC_TAG                    2018                                                   /**< Tag used to identify security credentials used by the client. */
#define APP_COAP_SEC_PSK                    "73656372657450534b30"                                 /**< Pre-shared key used for DTLS in hex format. */
#define APP_COAP_SEC_IDENTITY               "Client_identity"                                      /**< Client identity used for DTLS. */

static const char m_uri_part_lights[]  = "lights";
static const char m_uri_part_led3[]    = "led3";
static uint16_t   m_global_token_count = 0x0102;

APP_TIMER_DEF(m_iot_timer_tick_src_id);

#if defined(APP_USE_AF_INET6)

static struct sockaddr_in6 m_coap_server =
{
    .sin_port   = APP_COAP_REMOTE_SERVER_PORT,
    .sin_family = AF_INET6,
    .sin_len    = sizeof(struct sockaddr_in6)
};

static struct sockaddr_in6 m_coap_secure_server =
{
    .sin_port   = APP_COAP_REMOTE_SECURE_SERVER_PORT,
    .sin_family = AF_INET6,
    .sin_len    = sizeof(struct sockaddr_in6)
};

#else //APP_USE_AF_INET6

static struct sockaddr_in m_coap_server =
{
    .sin_port        = HTONS(APP_COAP_REMOTE_SERVER_PORT),
    .sin_family      = AF_INET,
    .sin_len         = sizeof(struct sockaddr_in),
    .sin_addr.s_addr = HTONL(0xC0A81EB0) //192.168.30.176
};

static struct sockaddr_in m_coap_secure_server =
{
    .sin_port        = HTONS(APP_COAP_REMOTE_SECURE_SERVER_PORT),
    .sin_family      = AF_INET,
    .sin_len         = sizeof(struct sockaddr_in),
    .sin_addr.s_addr = HTONL(0xC0A81EB0) // 192.168.30.176
};

#endif

static coap_transport_handle_t * mp_transport_handle;                                                            /**< Transport handle used for data exchange, obtained on @coap_init. */
static coap_transport_handle_t * mp_secure_transport_handle;                                                     /**< Transport handle used for secure data exchange, obtained on @coap_security_setup. */
static uint8_t                   m_app_coap_data_buffer[APP_COAP_MAX_BUFFER_SIZE];                               /**< Buffer contributed by CoAP for its use. */
static const struct sockaddr *   mp_coap_remote_server = (struct sockaddr *)&m_coap_server;                      /**< Pointer to remote server address to connect to. */
static const struct sockaddr *   mp_coap_secure_remote_server = (struct sockaddr *)&m_coap_secure_server;        /**< Pointer to remote secure server address to connect to. */

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


static void app_coap_request_send(void);
static void app_coap_secure_request_send(void);

/**@brief Handle application errors.
 *
 * @details Turn on all LEDs and halt.
 */
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
    (void)coap_time_tick();
    app_coap_request_send();
    app_coap_secure_request_send();
}


/**@brief Function to configure the modem and create a LTE connection. */
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


/**@brief Function for the Timer initialization.
 *
 * @details Initializes the timer module.
 */
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


/**@brief Initialize the IoT Timer.
 *
 * @details Start up IoT timer to generate ticks for LED, GPS and FLIP.
 */
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
        ARRAY_SIZE(list_of_clients),
        &(list_of_clients[0]),
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


/**@brief Application procc*/
static void app_process(void)
{
    coap_transport_input();
}


/**@brief Handles an errors notified by CoAP. */
static void app_coap_error_handler(uint32_t error_code, coap_message_t * p_message)
{
    // If any response fill the p_response with a appropriate response message.
}


/**@brief Handles responses from the remote CoAP server. */
static void app_coap_response_handle(uint32_t status, void * arg, coap_message_t * p_response)
{
    APP_ERROR_CHECK(status == NRF_SUCCESS);
}


/**@brief Method to send request as a client to a remote server. */
static void app_coap_request_send(void)
{
    #define COMMAND_TOGGLE                  0x32

    uint32_t             err_code;
    coap_message_t *     p_request;
    coap_message_conf_t  message_conf;

    memset(&message_conf, 0x00, sizeof(message_conf));
    message_conf.type        = COAP_TYPE_CON;
    message_conf.code        = COAP_CODE_PUT;
    message_conf.p_transport = mp_transport_handle;
    message_conf.id          = 0; // Auto-generate message ID.

    (void)uint16_encode(HTONS(m_global_token_count), message_conf.token);
    m_global_token_count++;

    message_conf.token_len         = 2;
    message_conf.response_callback = app_coap_response_handle;
    message_conf.p_transport       = mp_transport_handle;

    err_code = coap_message_new(&p_request, &message_conf);

    if (err_code == NRF_SUCCESS)
    {
        err_code = coap_message_remote_addr_set(p_request, (struct sockaddr *)mp_coap_remote_server);
        APP_ERROR_CHECK(err_code);

        err_code = coap_message_opt_str_add(p_request, COAP_OPT_URI_PATH, (uint8_t *)m_uri_part_lights, strlen(m_uri_part_lights));
        APP_ERROR_CHECK(err_code);

        err_code = coap_message_opt_str_add(p_request, COAP_OPT_URI_PATH, (uint8_t *)m_uri_part_led3, strlen(m_uri_part_led3));
        APP_ERROR_CHECK(err_code);

        uint8_t payload[] = {COMMAND_TOGGLE};
        err_code = coap_message_payload_set(p_request, payload, sizeof(payload));
        APP_ERROR_CHECK(err_code);

        uint32_t handle;
        err_code = coap_message_send(&handle, p_request);
        APP_ERROR_CHECK(err_code);

        err_code = coap_message_delete(p_request);
        APP_ERROR_CHECK(err_code);
    }
}


/**@brief Method to send request as a client to a remote server. */
static void app_coap_secure_request_send(void)
{
    #define COMMAND_TOGGLE                  0x32

    uint32_t             err_code;
    coap_message_t *     p_request;
    coap_message_conf_t  message_conf;

    memset(&message_conf, 0x00, sizeof(message_conf));
    message_conf.type        = COAP_TYPE_CON;
    message_conf.code        = COAP_CODE_PUT;
    message_conf.p_transport = mp_secure_transport_handle;
    message_conf.id          = 0; // Auto-generate message ID.

    (void)uint16_encode(HTONS(m_global_token_count), message_conf.token);
    m_global_token_count++;

    message_conf.token_len         = 2;
    message_conf.response_callback = app_coap_response_handle;
    message_conf.p_transport       = mp_secure_transport_handle;

    err_code = coap_message_new(&p_request, &message_conf);

    if (err_code == NRF_SUCCESS)
    {
        err_code = coap_message_remote_addr_set(p_request, (struct sockaddr *)mp_coap_secure_remote_server);
        APP_ERROR_CHECK(err_code);

        err_code = coap_message_opt_str_add(p_request, COAP_OPT_URI_PATH, (uint8_t *)m_uri_part_lights, strlen(m_uri_part_lights));
        APP_ERROR_CHECK(err_code);

        err_code = coap_message_opt_str_add(p_request, COAP_OPT_URI_PATH, (uint8_t *)m_uri_part_led3, strlen(m_uri_part_led3));
        APP_ERROR_CHECK(err_code);

        uint8_t payload[] = {COMMAND_TOGGLE};
        err_code = coap_message_payload_set(p_request, payload, sizeof(payload));
        APP_ERROR_CHECK(err_code);

        uint32_t handle;
        err_code = coap_message_send(&handle, p_request);
        APP_ERROR_CHECK(err_code);

        err_code = coap_message_delete(p_request);
        APP_ERROR_CHECK(err_code);
    }
}


/**@brief Initialize CoAP. */
static void app_coap_init(void)
{
    // Contribute memory needed for CoAP.
    nrf_mem_id_t mem_pid;
    uint32_t err_code = app_nrf_mem_register(&mem_pid, &app_coap_mem_desc);
    APP_ERROR_CHECK(err_code);


#if defined(APP_USE_AF_INET6)

    const struct sockaddr_in client_addr =
    {
        .sin6_port   = APP_COAP_LOCAL_CLIENT_PORT;
        .sin6_family = AF_INET6;
        .sin6_len    = sizeof(struct sockaddr_in6);
        .sin
    };

#else // APP_USE_AF_INET6

    const struct sockaddr_in client_addr =
    {
        .sin_port        = APP_COAP_LOCAL_CLIENT_PORT,
        .sin_family      = AF_INET,
        .sin_len         =  sizeof(struct sockaddr_in),
        .sin_addr.s_addr = 0
    };

#endif // APP_USE_AF_INET6

    struct sockaddr * p_localaddr = (struct sockaddr *)&client_addr;

    coap_local_t local_port_list[COAP_PORT_COUNT] =
    {
        {
            .p_addr    = p_localaddr,
            .protocol  = IPPROTO_UDP,
            .p_setting = NULL
        }
    };

    coap_transport_init_t port_list;
    port_list.p_port_table = &local_port_list[0];

    err_code = coap_init(829131, &port_list, app_nrf_malloc, app_nrf_free);
    APP_ERROR_CHECK(err_code);

    mp_transport_handle = local_port_list[0].p_transport;

    err_code = coap_error_handler_register(app_coap_error_handler);
    APP_ERROR_CHECK(err_code);
}


/**@brief Function to establish secure transport for the CoAP client. */
static void app_coap_security_setup(void)
{

#if defined (APP_USE_AF_INET6)

    const struct sockaddr_in client_addr =
    {
        .sin6_port   = APP_COAP_LOCAL_SECURE_CLIENT_PORT;
        .sin6_family = AF_INET6;
        .sin6_len    = sizeof(struct sockaddr_in6);
        .sin
    };

#else // APP_USE_AF_INET6

    const struct sockaddr_in client_addr =
    {
        .sin_port        = APP_COAP_LOCAL_SECURE_CLIENT_PORT,
        .sin_family      = AF_INET,
        .sin_len         =  sizeof(struct sockaddr_in),
        .sin_addr.s_addr = 0
    };

#endif // APP_USE_AF_INET6

    #define SEC_TAG_COUNT 1

    struct sockaddr * p_localaddr = (struct sockaddr *)&client_addr;
    nrf_sec_tag_t     sec_tag_list[SEC_TAG_COUNT] = {APP_COAP_SEC_TAG};

    nrf_sec_config_t setting =
    {
        .role           = 0,    // 0 -> Client role
        .sec_tag_count  = SEC_TAG_COUNT,
        .p_sec_tag_list = &sec_tag_list[0]
    };


    coap_local_t local_port =
    {
        .p_addr    = p_localaddr,
        .p_setting = &setting,
        .protocol  = SPROTO_DTLS1v2
    };

    // NOTE: This method initiates a DTLS handshake and may block for a some seconds.
    uint32_t err_code = coap_security_setup(&local_port, mp_coap_secure_remote_server);
    APP_ERROR_CHECK(err_code);

    mp_secure_transport_handle = local_port.p_transport;
}

#endif
/**@brief Function for application main entry. */
int main(void)
{
#if 0
    UNUSED_RETURN_VALUE(app_nrf_mem_init());

    bsd_init();

    app_provision();

    app_modem_configure();

    app_coap_init();

    app_coap_security_setup();

    timers_init();
    iot_timer_init();
#endif
    // Enter main loop.
    while (true)
    {
#if 0
        app_process();
#endif
    }
}
