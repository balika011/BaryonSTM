/*
 * Copyright (c) 2021 balika011
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/cm3/nvic.h>
#include <libopencm3/cm3/systick.h>
#include <libopencm3/stm32/usart.h>
#include <AES.h>
#include <string.h>

uint8_t serialno[] = {0xFF, 0xFF, 0xFF, 0xFF};

static void clock_setup(void)
{
	rcc_clock_setup_in_hse_8mhz_out_72mhz();

	rcc_periph_clock_enable(RCC_GPIOA);
	rcc_periph_clock_enable(RCC_GPIOB);
	rcc_periph_clock_enable(RCC_GPIOC);

	rcc_periph_clock_enable(RCC_AFIO);
	rcc_periph_clock_enable(RCC_USART2);
}

volatile uint32_t system_millis;

void sys_tick_handler(void)
{
	system_millis++;
}

static void systick_setup(void)
{
	systick_set_reload(72000);
	systick_set_clocksource(STK_CSR_CLKSOURCE_AHB);
	systick_counter_enable();
	systick_interrupt_enable();
}

static void usart_setup(void)
{
	gpio_set_mode(GPIOA, GPIO_MODE_OUTPUT_50_MHZ, GPIO_CNF_OUTPUT_ALTFN_OPENDRAIN, GPIO_USART2_TX);
	gpio_set_mode(GPIOA, GPIO_MODE_INPUT, GPIO_CNF_INPUT_PULL_UPDOWN, GPIO_USART2_RX);
	gpio_set(GPIOA, GPIO_USART2_RX);
	usart_set_baudrate(USART2, 19200);
	usart_set_databits(USART2, 9);
	usart_set_stopbits(USART2, USART_STOPBITS_1);
	usart_set_mode(USART2, USART_MODE_TX_RX);
	usart_set_parity(USART2, USART_PARITY_EVEN);
	usart_set_flow_control(USART2, USART_FLOWCONTROL_NONE);
	usart_enable(USART2);
}

struct challange_secret
{
	uint8_t version;
	uint8_t secret[8];
};

struct challange_secret secrets1[] =
{
	{0x00, {0xD2, 0x07, 0x22, 0x53, 0xA4, 0xF2, 0x74, 0x68}},
	{0x01, {0xF5, 0xD7, 0xD4, 0xB5, 0x75, 0xF0, 0x8E, 0x4E}},
	{0x02, {0xB3, 0x7A, 0x16, 0xEF, 0x55, 0x7B, 0xD0, 0x89}},
	{0x03, {0xCC, 0x69, 0x95, 0x81, 0xFD, 0x89, 0x12, 0x6C}},
	{0x04, {0xA0, 0x4E, 0x32, 0xBB, 0xA7, 0x13, 0x9E, 0x46}},
	{0x05, {0x49, 0x5E, 0x03, 0x47, 0x94, 0x93, 0x1D, 0x7B}},
	{0x06, {0xB0, 0xB8, 0x09, 0x83, 0x39, 0x89, 0xFA, 0xE2}},
	{0x08, {0xAD, 0x40, 0x43, 0xB2, 0x56, 0xEB, 0x45, 0x8B}},
	{0x0A, {0xC2, 0x37, 0x7E, 0x8A, 0x74, 0x09, 0x6C, 0x5F}},
	{0x0D, {0x58, 0x1C, 0x7F, 0x19, 0x44, 0xF9, 0x62, 0x62}},
	{0x2F, {0xF1, 0xBC, 0x56, 0x2B, 0xD5, 0x5B, 0xB0, 0x77}},
	{0x97, {0xAF, 0x60, 0x10, 0xA8, 0x46, 0xF7, 0x41, 0xF3}},
	{0xB3, {0xDB, 0xD3, 0xAE, 0xA4, 0xDB, 0x04, 0x64, 0x10}},
	{0xD9, {0x90, 0xE1, 0xF0, 0xC0, 0x01, 0x78, 0xE3, 0xFF}},
	{0xEB, {0x0B, 0xD9, 0x02, 0x7E, 0x85, 0x1F, 0xA1, 0x23}}

};

struct challange_secret secrets2[] =
{
	{0x00, {0xF4, 0xE0, 0x43, 0x13, 0xAD, 0x2E, 0xB4, 0xDB}},
	{0x01, {0xFE, 0x7D, 0x78, 0x99, 0xBF, 0xEC, 0x47, 0xC5}},
	{0x02, {0x86, 0x5E, 0x3E, 0xEF, 0x9D, 0xFB, 0xB1, 0xFD}},
	{0x03, {0x30, 0x6F, 0x3A, 0x03, 0xD8, 0x6C, 0xBE, 0xE4}},
	{0x04, {0xFF, 0x72, 0xBD, 0x2B, 0x83, 0xB8, 0x9D, 0x2F}},
	{0x05, {0x84, 0x22, 0xDF, 0xEA, 0xE2, 0x1B, 0x63, 0xC2}},
	{0x06, {0x58, 0xB9, 0x5A, 0xAE, 0xF3, 0x99, 0xDB, 0xD0}},
	{0x08, {0x67, 0xC0, 0x72, 0x15, 0xD9, 0x6B, 0x39, 0xA1}},
	{0x0A, {0x09, 0x3E, 0xC5, 0x19, 0xAF, 0x0F, 0x50, 0x2D}},
	{0x0D, {0x31, 0x80, 0x53, 0x87, 0x5C, 0x20, 0x3E, 0x24}},
	{0x2F, {0x1B, 0xDF, 0x24, 0x33, 0xEB, 0x29, 0x15, 0x5B}},
	{0x97, {0x9D, 0xEE, 0xC0, 0x11, 0x44, 0xB6, 0x6F, 0x41}},
	{0xB3, {0xE3, 0x2B, 0x8F, 0x56, 0xB2, 0x64, 0x12, 0x98}},
	{0xD9, {0xC3, 0x4A, 0x6A, 0x7B, 0x20, 0x5F, 0xE8, 0xF9}},
	{0xEB, {0xF7, 0x91, 0xED, 0x0B, 0x3F, 0x49, 0xA4, 0x48}}
};

struct challange_key
{
	uint8_t version;
	uint8_t key[16];
};

struct challange_key keys[] =
{
	{0x00, {0x5C, 0x52, 0xD9, 0x1C, 0xF3, 0x82, 0xAC, 0xA4, 0x89, 0xD8, 0x81, 0x78, 0xEC, 0x16, 0x29, 0x7B}},
	{0x01, {0x9D, 0x4F, 0x50, 0xFC, 0xE1, 0xB6, 0x8E, 0x12, 0x09, 0x30, 0x7D, 0xDB, 0xA6, 0xA5, 0xB5, 0xAA}},
	{0x02, {0x09, 0x75, 0x98, 0x88, 0x64, 0xAC, 0xF7, 0x62, 0x1B, 0xC0, 0x90, 0x9D, 0xF0, 0xFC, 0xAB, 0xFF}},
	{0x03, {0xC9, 0x11, 0x5C, 0xE2, 0x06, 0x4A, 0x26, 0x86, 0xD8, 0xD6, 0xD9, 0xD0, 0x8C, 0xDE, 0x30, 0x59}},
	{0x04, {0x66, 0x75, 0x39, 0xD2, 0xFB, 0x42, 0x73, 0xB2, 0x90, 0x3F, 0xD7, 0xA3, 0x9E, 0xD2, 0xC6, 0x0C}},
	{0x05, {0xF4, 0xFA, 0xEF, 0x20, 0xF4, 0xDB, 0xAB, 0x31, 0xD1, 0x86, 0x74, 0xFD, 0x8F, 0x99, 0x05, 0x66}},
	{0x06, {0xEA, 0x0C, 0x81, 0x13, 0x63, 0xD7, 0xE9, 0x30, 0xF9, 0x61, 0x13, 0x5A, 0x4F, 0x35, 0x2D, 0xDC}},
	{0x08, {0x0A, 0x2E, 0x73, 0x30, 0x5C, 0x38, 0x2D, 0x4F, 0x31, 0x0D, 0x0A, 0xED, 0x84, 0xA4, 0x18, 0x00}},
	{0x0A, {0xAC, 0x00, 0xC0, 0xE3, 0xE8, 0x0A, 0xF0, 0x68, 0x3F, 0xDD, 0x17, 0x45, 0x19, 0x45, 0x43, 0xBD}},
	{0x0D, {0xDF, 0xF3, 0xFC, 0xD6, 0x08, 0xB0, 0x55, 0x97, 0xCF, 0x09, 0xA2, 0x3B, 0xD1, 0x7D, 0x3F, 0xD2}},
	{0x2F, {0x4A, 0xA7, 0xC7, 0xB0, 0x11, 0x34, 0x46, 0x6F, 0xAC, 0x82, 0x16, 0x3E, 0x4B, 0xB5, 0x1B, 0xF9}},
	{0x97, {0xCA, 0xC8, 0xB8, 0x7A, 0xCD, 0x9E, 0xC4, 0x96, 0x90, 0xAB, 0xE0, 0x81, 0x39, 0x20, 0xB1, 0x10}},
	{0xB3, {0x03, 0xBE, 0xB6, 0x54, 0x99, 0x14, 0x04, 0x83, 0xBA, 0x18, 0x7A, 0x64, 0xEF, 0x90, 0x26, 0x1D}},
	{0xD9, {0xC7, 0xAC, 0x13, 0x06, 0xDE, 0xFE, 0x39, 0xEC, 0x83, 0xA1, 0x48, 0x3B, 0x0E, 0xE2, 0xEC, 0x89}},
	{0xEB, {0x41, 0x84, 0x99, 0xBE, 0x9D, 0x35, 0xA3, 0xB9, 0xFC, 0x6A, 0xD0, 0xD6, 0xF0, 0x41, 0xBB, 0x26}}
};

static char MixChallenge1(uint8_t version, uint8_t *challenge, uint8_t *data)
{
	uint8_t *secret1 = 0;

	for (int i = 0; i < sizeof(secrets1) / sizeof(secrets1[0]); i++)
	{
		if (secrets1[i].version == version)
			secret1 = secrets1[i].secret;
	}

	if (!secret1)
		return 0;

	data[0x00] = secret1[0];
	data[0x01] = secret1[1];
	data[0x02] = secret1[2];
	data[0x03] = secret1[3];
	data[0x04] = secret1[4];
	data[0x05] = secret1[5];
	data[0x06] = secret1[6];
	data[0x07] = secret1[7];

	data[0x08] = challenge[0];
	data[0x09] = challenge[1];
	data[0x0A] = challenge[2];
	data[0x0B] = challenge[3];
	data[0x0C] = challenge[4];
	data[0x0D] = challenge[5];
	data[0x0E] = challenge[6];
	data[0x0F] = challenge[7];

	return 1;
}

static char MixChallenge2(uint8_t version, uint8_t *challenge, uint8_t *data)
{
	uint8_t *secret2 = 0;

	for (int i = 0; i < sizeof(secrets2) / sizeof(secrets2[0]); i++)
	{
		if (secrets2[i].version == version)
			secret2 = secrets2[i].secret;
	}

	if (!secret2)
		return 0;

	data[0x00] = challenge[0];
	data[0x01] = challenge[1];
	data[0x02] = challenge[2];
	data[0x03] = challenge[3];
	data[0x04] = challenge[4];
	data[0x05] = challenge[5];
	data[0x06] = challenge[6];
	data[0x07] = challenge[7];

	data[0x08] = secret2[0];
	data[0x09] = secret2[1];
	data[0x0A] = secret2[2];
	data[0x0B] = secret2[3];
	data[0x0C] = secret2[4];
	data[0x0D] = secret2[5];
	data[0x0E] = secret2[6];
	data[0x0F] = secret2[7];

	return 1;
}

static char ECBEncryptBytes(uint8_t *clearBytes, uint8_t version, uint8_t *encryptedBytes)
{
	uint8_t *key = 0;
	for (int i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
	{
		if (keys[i].version == version)
			key = keys[i].key;
	}

	if (!key)
		return 0;

	AES_ctx ctx;
	AES_set_key(&ctx, key, 128);

	AES_encrypt(&ctx, clearBytes, encryptedBytes);

	return 1;
}

uint8_t BatteryNonce[8] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
uint8_t ChallangeVersion = 0;

static char GenerateResponse(uint8_t *req, uint8_t *resp)
{
	uint8_t data[16];
	if (!MixChallenge1(ChallangeVersion, req, data))
		return 0;

	if (!ECBEncryptBytes(data, ChallangeVersion, data))
		return 0;

	memcpy(resp, data, 8);

	return 1;
}

static char CheckResponse(uint8_t *req, uint8_t *resp)
{
	uint8_t data[16];
	if (!MixChallenge2(ChallangeVersion, BatteryNonce, data))
		return 0;

	if (!ECBEncryptBytes(data, ChallangeVersion, data))
		return 0;

	if (memcmp(req, data, 8) != 0)
		return 0;

	if (!ECBEncryptBytes(data, ChallangeVersion, data))
		return 0;

	memcpy(resp, data, 8);

	return 1;
}

enum COMMANDS
{
	CMD_READ_STATUS = 1,
	CMD_READ_TEMPERATURE,
	CMD_READ_VOLTAGE,
	CMD_READ_CURRENT,
	CMD_READ_CAPACITY = 7,
	CMD_READ_8,
	CMD_READ_TIME_LEFT,
	CMD_READ_11 = 11,
	CMD_READ_SERIALNO,
	CMD_READ_13,
	CMD_WRITE_EEPROM = 19, // 7 and 9 are the serial
	CMD_READ_EEPROM,
	CMD_READ_22 = 22,
	CMD_AUTH1 = 0x80,
	CMD_AUTH2
};

enum RESPONSE
{
	NAK = 5,
	ACK
};

static void receivePacket(uint8_t *recv, uint8_t *len)
{
	while (true)
	{
		uint16_t r = usart_recv_blocking(USART2);
		if ((uint8_t)r == 0x5A)
			break;
	}

	uint8_t length = usart_recv_blocking(USART2);
	if (len)
		*len = length - 1;

	for (int i = 0; i < length; i++)
	{
		uint32_t timeout = system_millis + 500;

			while (!usart_get_flag(USART2, USART_SR_RXNE))
			{
				if (timeout < system_millis)
				{
					*len = 0;
					return;
				}
			}

		recv[i] = usart_recv(USART2);
	}
}

static void sendPacket(uint8_t code, uint8_t *packet, uint8_t length)
{
	usart_send_blocking(USART2, 0xA5);
	usart_send_blocking(USART2, length + 2);
	usart_send_blocking(USART2, code);

	uint8_t sum = 0xA5 + code + length + 2;
	for (int i = 0; i < length; i++)
	{
		usart_send_blocking(USART2, packet[i]);
		sum += packet[i];
	}

	usart_send_blocking(USART2, ~sum);
}

int main(void)
{
	clock_setup();
	systick_setup();
	usart_setup();

	gpio_set_mode(GPIOC, GPIO_MODE_INPUT, GPIO_CNF_INPUT_PULL_UPDOWN, GPIO13);
	gpio_set(GPIOC, GPIO13);

	while (true)
	{
		uint8_t recv[256];
		uint8_t length;
		memset(recv, 0, 256);
		receivePacket(recv, &length);

		if (!length)
			continue;

		gpio_clear(GPIOC, GPIO13);

		switch (recv[0])
		{
			case CMD_READ_STATUS:
			{
				uint8_t response[] = {0x10, 0xC3, 0x06}; // 1731

				sendPacket(ACK, response, sizeof(response));
				break;
			}
			case CMD_READ_TEMPERATURE:
			{
				uint8_t response = 27;
				sendPacket(ACK, &response, sizeof(response));
				break;
			}
			case CMD_READ_VOLTAGE:
			{
				int voltage = 0;

				uint16_t response = voltage;
				sendPacket(ACK, &response, sizeof(response));
				break;
			}
			case CMD_READ_CURRENT:
			{
				uint16_t response = 4200;
				sendPacket(ACK, &response, sizeof(response));
				break;
			}
			case CMD_READ_CAPACITY:
			{
				uint16_t response = 1800;
				sendPacket(ACK, &response, sizeof(response));
				break;
			}
			case CMD_READ_8:
			{
				uint16_t response = 1250;
				sendPacket(ACK, &response, sizeof(response));
				break;
			}
			case CMD_READ_TIME_LEFT:
			{
				uint16_t response = 1025;
				sendPacket(ACK, &response, sizeof(response));
				break;
			}
			case CMD_READ_11:
			{
				uint16_t response = 15;
				sendPacket(ACK, &response, sizeof(response));
				break;
			}
			case CMD_READ_SERIALNO:
			{
				uint8_t sn[] = {serialno[1], serialno[0], serialno[3], serialno[2]};
				sendPacket(ACK, sn, sizeof(sn));
				break;
			}
			case CMD_READ_13:
			{
				uint8_t response[] = {0x9D, 0x10, 0x10, 0x28, 0x14};
				sendPacket(ACK, response, sizeof(response));
				break;
			}
			case CMD_READ_22:
			{
				uint8_t response[] = {'S', 'o', 'n', 'y', 'E', 'n', 'e', 'r', 'g', 'y', 'D', 'e', 'v', 'i', 'c', 'e', 's'};
				sendPacket(ACK, response, sizeof(response));
				break;
			}
			case CMD_AUTH1:
			{
				ChallangeVersion = recv[1];
				uint8_t challangeResponse[8];
				if (GenerateResponse(&recv[2], challangeResponse))
				{
					uint8_t response[16] = {};
					memcpy(&response[0], challangeResponse, 8);
					memcpy(&response[8], BatteryNonce, 8);
					sendPacket(ACK, response, sizeof(response));
				}
				else
				{
					sendPacket(NAK, 0, 0);
				}

				break;
			}
			case CMD_AUTH2:
			{
				uint8_t challangeResponse[8];
				if (CheckResponse(&recv[1], challangeResponse))
				{
					sendPacket(ACK, challangeResponse, sizeof(challangeResponse));
				}
				else
				{
					sendPacket(NAK, 0, 0);
				}

				break;
			}

			default:
			{
				sendPacket(NAK, 0, 0);
			}
		}
		
		gpio_set(GPIOC, GPIO13);
	}

	return 0;
}
