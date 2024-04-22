/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdint.h>
#include <stddef.h>

/** @brief Valid SUIT envelope, based on ../recovery_no_validate.yaml
 *
 */
const uint8_t manifest_recovery_no_validate_buf[] = {
	0xD8, 0x6B, 0xA2, 0x02, 0x58, 0x7A, 0x82, 0x58, 0x24, 0x82, 0x2F, 0x58, 0x20, 0xD4, 0x31,
	0x66, 0x54, 0x78, 0xE9, 0xD2, 0xA3, 0x06, 0x0E, 0xBC, 0x8F, 0x63, 0x36, 0x0B, 0x85, 0x74,
	0x34, 0x6B, 0xB9, 0xD9, 0x7A, 0xF7, 0x9E, 0x74, 0xB1, 0xB0, 0x51, 0x2A, 0xBC, 0xAB, 0xBF,
	0x58, 0x51, 0xD2, 0x84, 0x4A, 0xA2, 0x01, 0x26, 0x04, 0x45, 0x1A, 0x7F, 0xFF, 0xFF, 0xE0,
	0xA0, 0xF6, 0x58, 0x40, 0x42, 0xBC, 0xC1, 0x28, 0x47, 0xC4, 0xF9, 0x2A, 0xF0, 0xE7, 0x33,
	0x6C, 0x38, 0x87, 0x60, 0x47, 0x75, 0x8C, 0x09, 0xAC, 0x96, 0x35, 0x25, 0x61, 0xDA, 0x67,
	0xE5, 0x3B, 0xD9, 0xDF, 0x37, 0xE4, 0x7A, 0xF0, 0x49, 0xC1, 0x9B, 0x82, 0x27, 0x7E, 0x0B,
	0x69, 0x88, 0xBC, 0x83, 0xFB, 0x38, 0xE8, 0xDD, 0x29, 0x10, 0x22, 0x99, 0x56, 0x12, 0xFB,
	0xA1, 0xB6, 0x47, 0xE9, 0x06, 0x7C, 0xB8, 0xE8, 0x03, 0x58, 0x6C, 0xA5, 0x01, 0x01, 0x02,
	0x01, 0x03, 0x58, 0x3F, 0xA3, 0x02, 0x81, 0x82, 0x4A, 0x69, 0x43, 0x41, 0x4E, 0x44, 0x5F,
	0x4D, 0x46, 0x53, 0x54, 0x41, 0x00, 0x04, 0x58, 0x27, 0x82, 0x14, 0xA2, 0x01, 0x50, 0x76,
	0x17, 0xDA, 0xA5, 0x71, 0xFD, 0x5A, 0x85, 0x8F, 0x94, 0xE2, 0x8D, 0x73, 0x5C, 0xE9, 0xF4,
	0x02, 0x50, 0x74, 0xA0, 0xC6, 0xE7, 0xA9, 0x2A, 0x56, 0x00, 0x9C, 0x5D, 0x30, 0xEE, 0x87,
	0x8B, 0x06, 0xBA, 0x01, 0xA1, 0x00, 0xA0, 0x09, 0x43, 0x82, 0x0C, 0x00, 0x05, 0x82, 0x4C,
	0x6B, 0x49, 0x4E, 0x53, 0x54, 0x4C, 0x44, 0x5F, 0x4D, 0x46, 0x53, 0x54, 0x50, 0x74, 0xA0,
	0xC6, 0xE7, 0xA9, 0x2A, 0x56, 0x00, 0x9C, 0x5D, 0x30, 0xEE, 0x87, 0x8B, 0x06, 0xBA};

const size_t manifest_recovery_no_validate_len = sizeof(manifest_recovery_no_validate_buf);