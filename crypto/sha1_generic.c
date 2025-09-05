/*
 * Cryptographic API.
 *
 * SHA1 Secure Hash Algorithm.
 *
 * Derived from cryptoapi implementation, adapted for in-place
 * scatterlist interface.
 *
 * Copyright (c) Alan Smithee.
 * Copyright (c) Andrew McDonald <andrew@mcdonald.org.uk>
 * Copyright (c) Jean-Francois Dive <jef@linuxbe.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/crypto.h>
#include <linux/cryptohash.h>
#include <linux/types.h>
#include <crypto/sha.h>
#include <asm/byteorder.h>

struct sha1_ctx {
        u64 count;
        u32 state[5];
        u8 buffer[64];
};

static void sha1_init(struct crypto_tfm *tfm)
{
	struct sha1_ctx *sctx = crypto_tfm_ctx(tfm);
	static const struct sha1_ctx initstate = {
	  0,
	  { SHA1_H0, SHA1_H1, SHA1_H2, SHA1_H3, SHA1_H4 },
	  { 0, }
	};

	*sctx = initstate;
}

static void sha1_update(struct crypto_tfm *tfm, const u8 *data,
			unsigned int len)
{
	struct sha1_ctx *sctx = crypto_tfm_ctx(tfm);
	unsigned int partial, done;
	const u8 *src;

	partial = sctx->count & 0x3f;
	sctx->count += len;
	done = 0;
	src = data;

	if ((partial + len) > 63) {
		u32 temp[SHA_WORKSPACE_WORDS];

		if (partial) {
			done = -partial;
			memcpy(sctx->buffer + partial, data, done + 64);
			src = sctx->buffer;
		}

		do {
			sha_transform(sctx->state, src, temp);
			done += 64;
			src = data + done;
		} while (done + 63 < len);

		memset(temp, 0, sizeof(temp));
		partial = 0;
	}
	memcpy(sctx->buffer + partial, src, len - done);
}


/* Add padding and return the message digest. */
static void sha1_final(struct crypto_tfm *tfm, u8 *out)
{
	struct sha1_ctx *sctx = crypto_tfm_ctx(tfm);
	__be32 *dst = (__be32 *)out;
	u32 i, index, padlen;
	__be64 bits;
	static const u8 padding[64] = { 0x80, };

	bits = cpu_to_be64(sctx->count << 3);

	/* Pad out to 56 mod 64 */
	index = sctx->count & 0x3f;
	padlen = (index < 56) ? (56 - index) : ((64+56) - index);
	sha1_update(tfm, padding, padlen);

	/* Append length */
	sha1_update(tfm, (const u8 *)&bits, sizeof(bits));

	/* Store state in digest */
	for (i = 0; i < 5; i++)
		dst[i] = cpu_to_be32(sctx->state[i]);

	/* Wipe context */
	memset(sctx, 0, sizeof *sctx);
}

static struct crypto_alg alg = {
	.cra_name	=	"sha1",
	.cra_driver_name=	"sha1-generic",
	.cra_flags	=	CRYPTO_ALG_TYPE_DIGEST,
	.cra_blocksize	=	SHA1_BLOCK_SIZE,
	.cra_ctxsize	=	sizeof(struct sha1_ctx),
	.cra_module	=	THIS_MODULE,
	.cra_alignmask	=	3,
	.cra_list       =       LIST_HEAD_INIT(alg.cra_list),
	.cra_u		=	{ .digest = {
	.dia_digestsize	=	SHA1_DIGEST_SIZE,
	.dia_init   	= 	sha1_init,
	.dia_update 	=	sha1_update,
	.dia_final  	=	sha1_final } }
#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/cryptohash.h>
#include <linux/types.h>
#include <crypto/sha.h>
#include <crypto/sha1_base.h>
#include <asm/byteorder.h>

const u8 sha1_zero_message_hash[SHA1_DIGEST_SIZE] = {
	0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
	0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
	0xaf, 0xd8, 0x07, 0x09
};
EXPORT_SYMBOL_GPL(sha1_zero_message_hash);

static void sha1_generic_block_fn(struct sha1_state *sst, u8 const *src,
				  int blocks)
{
	u32 temp[SHA_WORKSPACE_WORDS];

	while (blocks--) {
		sha_transform(sst->state, src, temp);
		src += SHA1_BLOCK_SIZE;
	}
	memzero_explicit(temp, sizeof(temp));
}

int crypto_sha1_update(struct shash_desc *desc, const u8 *data,
		       unsigned int len)
{
	return sha1_base_do_update(desc, data, len, sha1_generic_block_fn);
}
EXPORT_SYMBOL(crypto_sha1_update);

static int sha1_final(struct shash_desc *desc, u8 *out)
{
	sha1_base_do_finalize(desc, sha1_generic_block_fn);
	return sha1_base_finish(desc, out);
}

int crypto_sha1_finup(struct shash_desc *desc, const u8 *data,
		      unsigned int len, u8 *out)
{
	sha1_base_do_update(desc, data, len, sha1_generic_block_fn);
	return sha1_final(desc, out);
}
EXPORT_SYMBOL(crypto_sha1_finup);

static struct shash_alg alg = {
	.digestsize	=	SHA1_DIGEST_SIZE,
	.init		=	sha1_base_init,
	.update		=	crypto_sha1_update,
	.final		=	sha1_final,
	.finup		=	crypto_sha1_finup,
	.descsize	=	sizeof(struct sha1_state),
	.base		=	{
		.cra_name	=	"sha1",
		.cra_driver_name=	"sha1-generic",
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	SHA1_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
};

static int __init sha1_generic_mod_init(void)
{
	return crypto_register_alg(&alg);
	return crypto_register_shash(&alg);
}

static void __exit sha1_generic_mod_fini(void)
{
	crypto_unregister_alg(&alg);
	crypto_unregister_shash(&alg);
}

module_init(sha1_generic_mod_init);
module_exit(sha1_generic_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SHA1 Secure Hash Algorithm");

MODULE_ALIAS("sha1");
MODULE_ALIAS_CRYPTO("sha1");
MODULE_ALIAS_CRYPTO("sha1-generic");
