/*
	mini - a Free Software replacement for the Nintendo/BroadOn IOS.
	crypto hardware support

Copyright (C) 2008, 2009	Haxx Enterprises <bushing@gmail.com>
Copyright (C) 2008, 2009	Sven Peter <svenpeter@gmail.com>

# This code is licensed to you under the terms of the GNU GPL, version 2;
# see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*/

#include "crypto.h"
#include "hollywood.h"
#include "utils.h"
#include "memory.h"
#include "irq.h"
#include "ipc.h"
#include "gecko.h"
#include "string.h"
#include "seeprom.h"

#define		AES_CMD_RESET	0
#define		AES_CMD_DECRYPT	0x9800

#define		SHA_CMD_RESET	0
#define		SHA_CMD_DECRYPT	0x8000

otp_t otp;
seeprom_t seeprom;

void crypto_read_otp(void)
{
	u32 *otpd = (u32*)&otp;
	int i;
	for (i=0; i< 0x20; i++) {
		write32(HW_OTPCMD,0x80000000|i);
		*otpd++ = read32(HW_OTPDATA);
	}
}

void crypto_read_seeprom(void)
{
	seeprom_read(&seeprom, 0, sizeof(seeprom) / 2);
}

void crypto_initialize(void)
{
	crypto_read_otp();
	crypto_read_seeprom();

	aes_reset();
	irq_enable(IRQ_AES);

	sha_reset();
	irq_enable(IRQ_SHA1);
}

void crypto_ipc(volatile ipc_request *req)
{
	switch (req->req) {
		case IPC_KEYS_GETOTP:
			memcpy((void *)req->args[0], &otp, sizeof(otp));
			dc_flushrange((void *)req->args[0], sizeof(otp));
			break;
		case IPC_KEYS_GETEEP:
			memcpy((void *)req->args[0], &seeprom, sizeof(seeprom));
			dc_flushrange((void *)req->args[0], sizeof(seeprom));
			break;
		default:
			gecko_printf("IPC: unknown SLOW CRYPTO request %04x\n",
					req->req);
	}
	ipc_post(req->code, req->tag, 0);
}


static int _aes_irq = 0;

void aes_irq(void)
{
	_aes_irq = 1;
}

static inline void aes_command(u16 cmd, u8 iv_keep, u32 blocks)
{
	if (blocks != 0)
		blocks--;
	_aes_irq = 0;
	write32(AES_CMD, (cmd << 16) | (iv_keep ? 0x1000 : 0) | (blocks&0x7f));
	while (read32(AES_CMD) & 0x80000000);
}

void aes_reset(void)
{
	write32(AES_CMD, 0);
	while (read32(AES_CMD) != 0);
}

void aes_set_iv(u8 *iv)
{
	int i;
	for(i = 0; i < 4; i++) {
		write32(AES_IV, *(u32 *)iv);
		iv += 4;
	}
}

void aes_empty_iv(void)
{
	int i;
	for(i = 0; i < 4; i++)
		write32(AES_IV, 0);
}

void aes_set_key(u8 *key)
{
	int i;
	for(i = 0; i < 4; i++) {
		write32(AES_KEY, *(u32 *)key);
		key += 4;
	}
}

void aes_decrypt(u8 *src, u8 *dst, u32 blocks, u8 keep_iv)
{
	int this_blocks = 0;
	while(blocks > 0) {
		this_blocks = blocks;
		if (this_blocks > 0x80)
			this_blocks = 0x80;

		write32(AES_SRC, dma_addr(src));
		write32(AES_DEST, dma_addr(dst));

		dc_flushrange(src, blocks * 16);
		dc_invalidaterange(dst, blocks * 16);

		ahb_flush_to(AHB_AES);
		aes_command(AES_CMD_DECRYPT, keep_iv, this_blocks);
		ahb_flush_from(AHB_AES);
		ahb_flush_to(AHB_STARLET);

		blocks -= this_blocks;
		src += this_blocks<<4;
		dst += this_blocks<<4;
		keep_iv = 1;
	}

}

void aes_ipc(volatile ipc_request *req)
{
	switch (req->req) {
		case IPC_AES_RESET:
			aes_reset();
			break;
		case IPC_AES_SETIV:
			aes_set_iv((u8 *)req->args);
			break;
		case IPC_AES_SETKEY:
			aes_set_key((u8 *)req->args);
			break;
		case IPC_AES_DECRYPT:
			aes_decrypt((u8 *)req->args[0], (u8 *)req->args[1],
				    req->args[2], req->args[3]);
			break;
		default:
			gecko_printf("IPC: unknown SLOW AES request %04x\n",
					req->req);
	}
	ipc_post(req->code, req->tag, 0);
}


void sha_reset(void) {
	//for some odd reason it didn't work without this check... 
	if(read32(SHA_CMD) != 0) {
		write32(SHA_CMD, 0);
		while (read32(SHA_CMD) != 0);
	}

	//initial values
	write32(SHA_H0, 0x67452301);
	write32(SHA_H1, 0xEFCDAB89);
	write32(SHA_H2, 0x98BADCFE);
	write32(SHA_H3, 0x10325476);
	write32(SHA_H4, 0xC3D2E1F0);
}


u32 hash[5];
void sha_decrypt(u8 *src, u32 blocks) {
	static u8 tmp[64] ALIGNED(64);
	memcpy(tmp, src, 64);
	u32 dmatmp = dma_addr(tmp);

	//write src adress 
	write32(SHA_SRC, dmatmp);

	dc_flushrange(tmp, blocks * 64);
	ahb_flush_to(AHB_SHA1);

	
	//write cmd
	if (blocks != 0)
		blocks--;
	//todo: find out value to AND with 'blocks'; for testing 'blocks' should be zero
	write32(SHA_CMD, (SHA_CMD_DECRYPT<< 16) | (blocks&0x7f)); 	
	while (read32(SHA_CMD) & 0x80000000);

	//read result
	hash[0] = read32(SHA_H0);
	hash[1] = read32(SHA_H1);
	hash[2] = read32(SHA_H2);
	hash[3] = read32(SHA_H3);
	hash[4] = read32(SHA_H4);
}

void sha_ipc(volatile ipc_request *req) {
	switch(req->req) {
		case IPC_SHA_RESET:
			sha_reset();
			gecko_printf("[mini] sha_reset@IPC\n");
			ipc_post(req->code, req->tag, 0);
			break;
		case IPC_SHA_DECRYPT:
			dc_invalidaterange((u8 *)req->args[0], (req->args[1]+1)*64);
			sha_decrypt((u8 *)req->args[0], req->args[1]);
			ipc_post(req->code, req->tag, 5, hash[0], hash[1], hash[2], hash[3], hash[4]);
			break;
		default:
			gecko_printf("IPC: unknown SLOW SHA request %04x\n", req->req);
			ipc_post(req->code, req->tag, 0);
	}
}

