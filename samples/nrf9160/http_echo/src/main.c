/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <string.h>

#include <zephyr.h>
#include <net/socket.h>
#include <net/tls_credentials.h>

#include <lte_lc.h>

#if defined(CONFIG_BSD_LIBRARY)
#include <nrf_inbuilt_key.h>
#endif

#define CA_CERTIFICATE_TAG 1

u8_t ca_root_cert[] =
#if defined(CONFIG_BSD_LIBRARY)
	"-----BEGIN CERTIFICATE-----\r\n"
	"MIIESTCCAzGgAwIBAgITBn+UV4WH6Kx33rJTMlu8mYtWDTANBgkqhkiG9w0BAQsF\r\n"
	"ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\r\n"
	"b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL\r\n"
	"MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB\r\n"
	"IDFCMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\r\n"
	"AoIBAQDCThZn3c68asg3Wuw6MLAd5tES6BIoSMzoKcG5blPVo+sDORrMd4f2AbnZ\r\n"
	"cMzPa43j4wNxhplty6aUKk4T1qe9BOwKFjwK6zmxxLVYo7bHViXsPlJ6qOMpFge5\r\n"
	"blDP+18x+B26A0piiQOuPkfyDyeR4xQghfj66Yo19V+emU3nazfvpFA+ROz6WoVm\r\n"
	"B5x+F2pV8xeKNR7u6azDdU5YVX1TawprmxRC1+WsAYmz6qP+z8ArDITC2FMVy2fw\r\n"
	"0IjKOtEXc/VfmtTFch5+AfGYMGMqqvJ6LcXiAhqG5TI+Dr0RtM88k+8XUBCeQ8IG\r\n"
	"KuANaL7TiItKZYxK1MMuTJtV9IblAgMBAAGjggE7MIIBNzASBgNVHRMBAf8ECDAG\r\n"
	"AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUWaRmBlKge5WSPKOUByeW\r\n"
	"dFv5PdAwHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH\r\n"
	"AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy\r\n"
	"dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy\r\n"
	"dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js\r\n"
	"LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBMGA1UdIAQMMAow\r\n"
	"CAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IBAQCFkr41u3nPo4FCHOTjY3NTOVI1\r\n"
	"59Gt/a6ZiqyJEi+752+a1U5y6iAwYfmXss2lJwJFqMp2PphKg5625kXg8kP2CN5t\r\n"
	"6G7bMQcT8C8xDZNtYTd7WPD8UZiRKAJPBXa30/AbwuZe0GaFEQ8ugcYQgSn+IGBI\r\n"
	"8/LwhBNTZTUVEWuCUUBVV18YtbAiPq3yXqMB48Oz+ctBWuZSkbvkNodPLamkB2g1\r\n"
	"upRyzQ7qDn1X8nn8N8V7YJ6y68AtkHcNSRAnpTitxBKjtKPISLMVCx7i4hncxHZS\r\n"
	"yLyKQXhw2W2Xs0qLeC1etA+jTGDK4UfLeC0SF7FSi8o5LL21L8IzApar2pR/\r\n"
	"-----END CERTIFICATE-----";
#else
	"-----BEGIN CERTIFICATE-----\n"
	"MIIESTCCAzGgAwIBAgITBn+UV4WH6Kx33rJTMlu8mYtWDTANBgkqhkiG9w0BAQsF\n"
	"ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n"
	"b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL\n"
	"MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB\n"
	"IDFCMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
	"AoIBAQDCThZn3c68asg3Wuw6MLAd5tES6BIoSMzoKcG5blPVo+sDORrMd4f2AbnZ\n"
	"cMzPa43j4wNxhplty6aUKk4T1qe9BOwKFjwK6zmxxLVYo7bHViXsPlJ6qOMpFge5\n"
	"blDP+18x+B26A0piiQOuPkfyDyeR4xQghfj66Yo19V+emU3nazfvpFA+ROz6WoVm\n"
	"B5x+F2pV8xeKNR7u6azDdU5YVX1TawprmxRC1+WsAYmz6qP+z8ArDITC2FMVy2fw\n"
	"0IjKOtEXc/VfmtTFch5+AfGYMGMqqvJ6LcXiAhqG5TI+Dr0RtM88k+8XUBCeQ8IG\n"
	"KuANaL7TiItKZYxK1MMuTJtV9IblAgMBAAGjggE7MIIBNzASBgNVHRMBAf8ECDAG\n"
	"AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUWaRmBlKge5WSPKOUByeW\n"
	"dFv5PdAwHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH\n"
	"AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy\n"
	"dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy\n"
	"dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js\n"
	"LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBMGA1UdIAQMMAow\n"
	"CAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IBAQCFkr41u3nPo4FCHOTjY3NTOVI1\n"
	"59Gt/a6ZiqyJEi+752+a1U5y6iAwYfmXss2lJwJFqMp2PphKg5625kXg8kP2CN5t\n"
	"6G7bMQcT8C8xDZNtYTd7WPD8UZiRKAJPBXa30/AbwuZe0GaFEQ8ugcYQgSn+IGBI\n"
	"8/LwhBNTZTUVEWuCUUBVV18YtbAiPq3yXqMB48Oz+ctBWuZSkbvkNodPLamkB2g1\n"
	"upRyzQ7qDn1X8nn8N8V7YJ6y68AtkHcNSRAnpTitxBKjtKPISLMVCx7i4hncxHZS\n"
	"yLyKQXhw2W2Xs0qLeC1etA+jTGDK4UfLeC0SF7FSi8o5LL21L8IzApar2pR/\n"
	"-----END CERTIFICATE-----";
#endif

#define SERVER_URL "postman-echo.com"
#define SERVER_PORT 443

#if defined(CONFIG_BSD_LIBRARY)
/**@brief Recoverable BSD library error. */
void bsd_recoverable_error_handler(uint32_t err)
{
	printk("bsdlib recoverable error: %u\n", (unsigned int)err);
}

/**@brief Irrecoverable BSD library error. */
void bsd_irrecoverable_error_handler(uint32_t err)
{
	printk("bsdlib irrecoverable error: %u\n", (unsigned int)err);

	__ASSERT_NO_MSG(false);
}
#endif /* defined(CONFIG_BSD_LIBRARY) */

static int server_resolve(struct sockaddr_storage *server)
{

	int err;
	struct addrinfo *result;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM
	};
	char ipv4_addr[NET_IPV4_ADDR_LEN];

	err = getaddrinfo(SERVER_URL, NULL, &hints, &result);
	if (err != 0) {
		printk("ERROR: getaddrinfo failed %d\n", err);
		return -EIO;
	}

	if (result == NULL) {
		printk("ERROR: Address not found\n");
		return -ENOENT;
	}

	/* IPv4 Address. */
	struct sockaddr_in *server4 = ((struct sockaddr_in *)server);

	server4->sin_addr.s_addr =
		((struct sockaddr_in *)result->ai_addr)->sin_addr.s_addr;
	server4->sin_family = AF_INET;
	server4->sin_port = htons(SERVER_PORT);

	inet_ntop(AF_INET, &server4->sin_addr.s_addr, ipv4_addr,
		  sizeof(ipv4_addr));
	printk("IPv4 Address found %s\n", ipv4_addr);

	/* Free the address. */
	freeaddrinfo(result);

	return 0;
}

#if defined(CONFIG_BSD_LIBRARY)
static void modem_configure(void)
{
#if defined(CONFIG_LTE_LINK_CONTROL)
	if (IS_ENABLED(CONFIG_LTE_AUTO_INIT_AND_CONNECT)) {
		/* Do nothing, modem is already turned on
		 * and connected.
		 */
	} else {
		int err;

		printk("LTE Link Connecting ...\n");
		err = lte_lc_init_and_connect();
		__ASSERT(err == 0, "LTE link could not be established.");
		printk("LTE Link Connected!\n");
	}
#endif /* defined(CONFIG_LTE_LINK_CONTROL) */
}
#endif

void main(void)
{
	struct sockaddr_storage server;
	int err, sock, ret;

	printk("The HTTP echo sample started\n");

#if defined(CONFIG_BSD_LIBRARY)
	err = nrf_inbuilt_key_write(CA_CERTIFICATE_TAG,
				    NRF_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				    ca_root_cert, strlen(ca_root_cert));
#else
	err = tls_credential_add(CA_CERTIFICATE_TAG,
				 TLS_CREDENTIAL_CA_CERTIFICATE,
				 ca_root_cert, sizeof(ca_root_cert));
#endif
	if (err != 0) {
		printk("Failed to store certificate err: %d", err);
		return;
	}

#if defined(CONFIG_BSD_LIBRARY)
	modem_configure();
#endif

	err = server_resolve(&server);
	if (err != 0) {
		printk("Failed to resolve server name %d\n", err);
		return;
	}

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (sock < 0) {
		printk("Failed to open socket %d\n", errno);
		return;
	}

	sec_tag_t sec_tag_opt[] = {
		CA_CERTIFICATE_TAG,
	};

	err = setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST,
			 sec_tag_opt, sizeof(sec_tag_opt));
	if (err < 0) {
		printk("Failed to set socket option %d\n", errno);
		goto exit;
	}

	err = setsockopt(sock, SOL_TLS, TLS_HOSTNAME,
			 SERVER_URL, sizeof(SERVER_URL));
	if (err < 0) {
		printk("Failed to set socket option %d\n", errno);
		goto exit;
	}

	printk("Connecting...\n");

	ret = connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_in));
	if (ret < 0) {
		printk("Failed to connect %d\n", errno);
		goto exit;
	}

#define PAYLOAD_LENGTH 800
#define ITERATIONS 20

	static const char request[] =
		"POST /post HTTP/1.1\r\n"
		"Host: postman-echo.com\r\n"
		"Connection: keep-alive\r\n"
		"Accept: */*\r\n"
		"Content-Length: "STRINGIFY(PAYLOAD_LENGTH)"\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n\r\n";

	printk("Sending: \n%s\n", request);

	ret = send(sock, request, sizeof(request) - 1, 0);
	if (ret < 0) {
		printk("Failed to send %d\n", errno);
		goto exit;
	}

	char payload[PAYLOAD_LENGTH/ITERATIONS];

	memset(payload, 'a', sizeof(payload));

	for (int i = 0; i < ITERATIONS; i++) {
		ret = send(sock, payload, sizeof(payload), 0);
		if (ret < 0) {
			printk("Failed to send %d\n", errno);
			goto exit;
		}

		printk("#%02d Sent %lu bytes\n", i, sizeof(payload));
	}

	static char response[2048];

	ret = recv(sock, response, sizeof(response), 0);
	if (ret < 0) {
		printk("Failed to send %d\n", errno);
		goto exit;
	} else if (ret == 0) {
		printk("Connection closed\n");
		goto exit;
	} else {
		printk("Received %d bytes\n", ret);
	}

	response[ret] = '\0';
	printk("%s\n", response);

exit:
	(void)close(sock);
}
