/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <ctype.h>
#include <drivers/gpio.h>
#include <stdio.h>
#include <net/lwm2m.h>
#include <modem/bsdlib.h>
#include <settings/settings.h>

#include <logging/log.h>
LOG_MODULE_REGISTER(app_lwm2m_client, CONFIG_APP_LOG_LEVEL);

#include <modem/at_cmd.h>
#include <modem/lte_lc.h>

#if defined(CONFIG_LWM2M_DTLS_SUPPORT)
#if defined(CONFIG_MODEM_KEY_MGMT)
#include <modem/modem_key_mgmt.h>
#endif
#endif

#include "ui.h"
#include "lwm2m_client.h"
#include "settings.h"

#if !defined(CONFIG_LTE_LINK_CONTROL)
#error "Missing CONFIG_LTE_LINK_CONTROL"
#endif

BUILD_ASSERT(sizeof(CONFIG_APP_LWM2M_SERVER) > 1,
		 "CONFIG_APP_LWM2M_SERVER must be set in prj.conf");

#define APP_BANNER "Run LWM2M client"

#define IMEI_LEN		15
#define ENDPOINT_NAME_LEN	(IMEI_LEN + 8)

static uint8_t endpoint_name[ENDPOINT_NAME_LEN+1];
static uint8_t imei_buf[IMEI_LEN + 5]; /* account for /n/r */
static struct lwm2m_ctx client;

#if defined(CONFIG_LWM2M_DTLS_SUPPORT)
#include "config.h"
#endif /* CONFIG_LWM2M_DTLS_SUPPORT */

static struct k_sem lwm2m_start;
static struct k_sem lwm2m_stop;

static struct k_timer restart_timer;

/**@brief User interface event handler. */
static void ui_evt_handler(struct ui_evt *evt)
{
	if (!evt) {
		return;
	}

	LOG_DBG("Event: %d", evt->button);

#if defined(CONFIG_UI_BUTTON)
	if (handle_button_events(evt) == 0) {
		return;
	}
#endif
#if defined(CONFIG_LWM2M_IPSO_ACCELEROMETER) && CONFIG_FLIP_INPUT > 0
	if (handle_accel_events(evt) == 0) {
		return;
	}
#endif
}

static int remove_whitespace(char *buf)
{
	size_t i, j = 0, len;

	len = strlen(buf);
	for (i = 0; i < len; i++) {
		if (buf[i] >= 32 && buf[i] <= 126) {
			if (j != i) {
				buf[j] = buf[i];
			}

			j++;
		}
	}

	if (j < len) {
		buf[j] = '\0';
	}

	return 0;
}

static int query_modem(const char *cmd, char *buf, size_t buf_len)
{
	int ret;
	enum at_cmd_state at_state;

	ret = at_cmd_write(cmd, buf, buf_len, &at_state);
	if (ret) {
		LOG_ERR("at_cmd_write [%s] error:%d, at_state: %d",
			cmd, ret, at_state);
		strncpy(buf, "error", buf_len);
		return ret;
	}

	remove_whitespace(buf);
	return 0;
}

static int lwm2m_setup(void)
{
	/* use IMEI as serial number */
	lwm2m_init_device(imei_buf);
	lwm2m_init_security(&client, endpoint_name);
#if defined(CONFIG_LWM2M_LOCATION_OBJ_SUPPORT)
	lwm2m_init_location();
#endif
#if defined(CONFIG_LWM2M_FIRMWARE_UPDATE_OBJ_SUPPORT)
	lwm2m_init_firmware();
#endif
#if defined(CONFIG_LWM2M_CONN_MON_OBJ_SUPPORT)
	lwm2m_init_connmon();
#endif
#if defined(CONFIG_LWM2M_IPSO_LIGHT_CONTROL)
	lwm2m_init_light_control();
#endif
#if defined(CONFIG_LWM2M_IPSO_TEMP_SENSOR)
	lwm2m_init_temp();
#endif
#if defined(CONFIG_UI_BUZZER)
	lwm2m_init_buzzer();
#endif
#if defined(CONFIG_UI_BUTTON)
	lwm2m_init_button();
#endif
#if defined(CONFIG_LWM2M_IPSO_ACCELEROMETER)
	lwm2m_init_accel();
#endif
	return 0;
}

static void rd_client_event(struct lwm2m_ctx *client,
			    enum lwm2m_rd_client_event client_event)
{
	switch (client_event) {

	case LWM2M_RD_CLIENT_EVENT_NONE:
		/* do nothing */
		break;

	case LWM2M_RD_CLIENT_EVENT_BOOTSTRAP_REG_FAILURE:
		LOG_DBG("Bootstrap registration failure!");
		break;

	case LWM2M_RD_CLIENT_EVENT_BOOTSTRAP_REG_COMPLETE:
		LOG_DBG("Bootstrap registration complete");
		break;

	case LWM2M_RD_CLIENT_EVENT_BOOTSTRAP_TRANSFER_COMPLETE:
		LOG_DBG("Bootstrap transfer complete");
		break;

	case LWM2M_RD_CLIENT_EVENT_REGISTRATION_FAILURE:
		LOG_DBG("Registration failure!");
		break;

	case LWM2M_RD_CLIENT_EVENT_REGISTRATION_COMPLETE:
		LOG_DBG("Registration complete");
		break;

	case LWM2M_RD_CLIENT_EVENT_REG_UPDATE_FAILURE:
		LOG_DBG("Registration update failure!");
		break;

	case LWM2M_RD_CLIENT_EVENT_REG_UPDATE_COMPLETE:
		LOG_DBG("Registration update complete");
		break;

	case LWM2M_RD_CLIENT_EVENT_DEREGISTER_FAILURE:
		LOG_DBG("Deregister failure!");
		break;

	case LWM2M_RD_CLIENT_EVENT_DISCONNECT:
		LOG_DBG("Disconnected");
		break;

	case LWM2M_RD_CLIENT_EVENT_QUEUE_MODE_RX_OFF:
		LOG_DBG("Queue mode RX window closed");
		break;

	case LWM2M_RD_CLIENT_EVENT_NETWORK_ERROR:
		LOG_ERR("LwM2M engine reported a network erorr.");
		k_sem_give(&lwm2m_stop);
		k_timer_start(&restart_timer, K_MINUTES(10), K_NO_WAIT);
		break;
	}
}

#if defined(CONFIG_BSD_LIBRARY)
static void lte_handler(const struct lte_lc_evt *const evt)
{
	switch (evt->type) {
	case LTE_LC_EVT_NW_REG_STATUS:
		if ((evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_HOME) ||
		    (evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_ROAMING)) {
			LOG_INF("Network registration status: %s",
			evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_HOME ?
			"Connected - home network" : "Connected - roaming");

			k_sem_give(&lwm2m_start);
			k_timer_stop(&restart_timer);
		}
		break;
	case LTE_LC_EVT_PSM_UPDATE:
		LOG_INF("PSM parameter update: TAU: %d, Active time: %d",
			evt->psm_cfg.tau, evt->psm_cfg.active_time);
		break;
	case LTE_LC_EVT_EDRX_UPDATE: {
		char log_buf[60];
		ssize_t len;

		len = snprintf(log_buf, sizeof(log_buf),
			       "eDRX parameter update: eDRX: %0.2f, PTW: %0.2f",
			       evt->edrx_cfg.edrx, evt->edrx_cfg.ptw);
		if ((len > 0) && (len <= sizeof(log_buf))) {
			LOG_INF("%s", log_strdup(log_buf));
		}
		break;
	}
	case LTE_LC_EVT_RRC_UPDATE:
		LOG_INF("RRC mode: %s",
			evt->rrc_mode == LTE_LC_RRC_MODE_CONNECTED ?
			"Connected" : "Idle");
		break;
	case LTE_LC_EVT_CELL_UPDATE:
		LOG_INF("LTE cell changed: Cell ID: %d, Tracking area: %d",
			evt->cell.id, evt->cell.tac);
		break;
	default:
		break;
	}
}
#endif /* CONFIG_BSD_LIBRARY */

void restart_timer_handler(struct k_timer *timer_id)
{
	ARG_UNUSED(timer_id);

	k_sem_give(&lwm2m_start);
}

void main(void)
{
	int ret;

	LOG_INF(APP_BANNER);

	k_sem_init(&lwm2m_start, 1, 1);
	k_sem_init(&lwm2m_stop, 0, 1);
	k_timer_init(&restart_timer, restart_timer_handler, NULL);

	ui_init(ui_evt_handler);

	ret = fota_settings_init();
	if (ret < 0) {
		LOG_ERR("Unable to init settings (%d)", ret);
		return;
	}

	/* Load *all* persistent settings */
	settings_load();

#if defined(CONFIG_BSD_LIBRARY)
	lte_lc_register_handler(lte_handler);
#endif /* CONFIG_BSD_LIBRARY */

	LOG_INF("Initializing modem.");
	ret = lte_lc_init();
	if (ret < 0) {
		LOG_ERR("Unable to init modem (%d)", ret);
		return;
	}

	/* query IMEI */
	query_modem("AT+CGSN", imei_buf, sizeof(imei_buf));
	/* use IMEI as unique endpoint name */
	snprintf(endpoint_name, sizeof(endpoint_name), "nrf-%s", imei_buf);
	LOG_INF("endpoint: %s", log_strdup(endpoint_name));

	/* Setup LwM2M */
	(void)memset(&client, 0x0, sizeof(client));

	/* Workaround for improperly initialized socket fd in lwm2m engine. */
	client.sock_fd = -1;

	ret = lwm2m_setup();
	if (ret < 0) {
		LOG_ERR("Cannot setup LWM2M fields (%d)", ret);
		return;
	}

	ret = lwm2m_init_image();
	if (ret < 0) {
		LOG_ERR("Failed to setup image properties (%d)", ret);
		return;
	}

#if defined(CONFIG_LWM2M_DTLS_SUPPORT)
	ret = modem_key_mgmt_write(client.tls_tag,
				   MODEM_KEY_MGMT_CRED_TYPE_PSK,
				   client_psk, strlen(client_psk));
	if (ret < 0) {
		LOG_ERR("Error setting cred tag %d type %d: Error %d",
			client.tls_tag, MODEM_KEY_MGMT_CRED_TYPE_PSK,
			ret);
	}

	ret = modem_key_mgmt_write(client.tls_tag,
				   MODEM_KEY_MGMT_CRED_TYPE_IDENTITY,
				   endpoint_name, strlen(endpoint_name));
	if (ret < 0) {
		LOG_ERR("Error setting cred tag %d type %d: Error %d",
			client.tls_tag, MODEM_KEY_MGMT_CRED_TYPE_IDENTITY,
			ret);
	}
#endif

	/* setup modem */
	LOG_INF("Connecting to LTE network.");
	LOG_INF("This may take several minutes.");
	ui_led_set_pattern(UI_LTE_CONNECTING);

	ret = lte_lc_connect();
	__ASSERT(ret == 0, "LTE link could not be established.");

	LOG_INF("Connected to LTE network");
	ui_led_set_pattern(UI_LTE_CONNECTED);

#if defined(CONFIG_LWM2M_QUEUE_MODE_ENABLED)
	ret = lte_lc_psm_req(true);
	if (ret < 0) {
		LOG_ERR("lte_lc_psm_req, error: %d", ret);
	} else {
		LOG_INF("PSM mode requested");
	}
#endif

#if defined(CONFIG_LWM2M_CONN_MON_OBJ_SUPPORT)
	ret = lwm2m_start_connmon();
	if (ret < 0) {
		LOG_ERR("Error registering rsrp handler (%d)", ret);
	}
#endif

	while (1) {
		k_sem_take(&lwm2m_start, K_FOREVER);
		lwm2m_rd_client_start(&client, endpoint_name, rd_client_event);
		k_sem_take(&lwm2m_stop, K_FOREVER);
		lwm2m_rd_client_stop(&client, rd_client_event);
	}
}
