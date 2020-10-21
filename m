Return-Path: <kasan-dev+bncBDY3NC743AGBBVUJYL6AKGQEQXL6K2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id EC785295291
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 20:58:31 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id v7sf925236ots.19
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 11:58:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603306710; cv=pass;
        d=google.com; s=arc-20160816;
        b=j80X6Qpamr5ybnd2hwqvpUsliBy6tMzo1pTlFR5gpcNTlWl2e6NmHsbFEqMBPhm6sQ
         M3ejRGAhDFv/TdLcGoxClD/AX6+9WlW9pJeprULhJwXfkI6KVbxdLBL6YCuyj/qxgflE
         1QEwsoOWSjeiWKH6xjDfLka5dXMsnBWS836gho63WR3+K1RMzhEZj4p3AL+gber5NpS7
         4zLc55jbL5HkoayaIvpBwo/89G1AKnp6COplyjlRgxTY2aKh5zRysw5Dt9Qx6z+QBVWT
         hGf3VcYaP3++hKTMhrEXVt9GjdxsNKdcFt2obJrxsI2de1XJJGXP3jdL1hj6qOikrErr
         aKPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:date:cc:to
         :from:subject:message-id:sender:dkim-signature;
        bh=gSVKA6L50hLEIUZznZVnBjXPDSNelovuu9uIA3Y+PSs=;
        b=d4YxuvZ+K4jvVtvDqj3doymzzYDH6+w6aUvYUDTgf/HwUGFv52tz4exOGPgnTZCa2K
         Zi7mzlq3USMH2ULZzMlewZ4d9TIQb8jUp465ZXeRKkr2mcXt5BdhgCIRbpkhqVY0N6GY
         PK2ohjx5r2iTAI6TMRiSrfjIJ5RH0kuN2zfM02ZUutLBqxzg6VipIWfo/Xo5g9hwJwj7
         YPvE1BNCbXWU+VbT88dcG4fhPIzrEV4rHXHQZcYeZuVgfzX9DBpP8cNZBB/PsBQiix26
         JjLLb8wQol17p6abT43nPk543/lff2gzGSgJ1DBQPlHAysqzt3fNeo5VMUetiI714bX7
         Z5jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.249 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:user-agent:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gSVKA6L50hLEIUZznZVnBjXPDSNelovuu9uIA3Y+PSs=;
        b=BKV9v7FK5uLaZimbyJLhlBwhHsoSgRvxB4dGk1brZqL0Ni64LG7r7TqdNzh3Fp8Q+b
         PYsWk64O2SCt4zuHY+4CoGOdHlowr/jzDlrTmqnaV2RoIBBbrwF2DxkrY9w9OOovmy+v
         LnAKh7dzdZobe8b/LtxfNZ8u3ux9vFs77Iqfbx9tTHlzdVTMZu8KiNdXWP9SmHyDI9iv
         R2JjaoTwNMMuIM9N7BurxEfo0b9ppIImXmBc7TvzPMWd5g13DeA2EjkrAePFg3iHgbJg
         i+94uFTmc5Yq0Z0tburHj2ovk3eDtKAr+CuxOclE0ngYMoAktVpPn5TMZHBZyxelfbbC
         uvsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gSVKA6L50hLEIUZznZVnBjXPDSNelovuu9uIA3Y+PSs=;
        b=tkyp1rifSaGvoBrjo+EXwDW+vayxw634lStktXcAfVaMayRq4l8Oe9eESTGnmQjuix
         fiHC22ysqRRXQG1MIaT3wxTqf9i2mioPXG4clTHaewxbm1jvN0p1wjkjZnr0Dw/16jCJ
         eh1ymh4v1Z34T+e9AVltOcw//3ZYchIR0SEF4SBwCywWeDl/YRG3sRcsAkHTYiv/SIpw
         q/9gTPT03FC3gGTOI0Inf/AR7M4/YCqeH4udp224K+T7duPHdxvn71/O4oxMnviAcseO
         MtFHwxhXj9iwBJxpxJ4cNSGgZCCGr6sN+38NAshIjalhzzM1ySHhacROSUEYW5wcMk/J
         l2Tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530h/Ixa3Zwp23xAx2UAO3nxlJoVtGplqp7FpYZZbiZnoahIMppE
	NInzhthY0J+DFm+HBjNuH1o=
X-Google-Smtp-Source: ABdhPJzVuYCuWlOYWz87U5Myvet/Iwp0aGkWYAHlbXylhOJ67cDuv/ONK4WSMwOoJk4huLJerOhYtQ==
X-Received: by 2002:a4a:ba82:: with SMTP id d2mr3587692oop.43.1603306710765;
        Wed, 21 Oct 2020 11:58:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d650:: with SMTP id n77ls160386oig.5.gmail; Wed, 21 Oct
 2020 11:58:30 -0700 (PDT)
X-Received: by 2002:a05:6808:2d2:: with SMTP id a18mr3421298oid.33.1603306710294;
        Wed, 21 Oct 2020 11:58:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603306710; cv=none;
        d=google.com; s=arc-20160816;
        b=UKXBJ6a9+VTmd8lrzITqYiDI0Z7r02i8WXFoND/CiZP1mnl4Qo1+6FUy9NTd9oN4Ox
         1HDuvXUqklOBbL28iu5vurv71naxoip3nvnQXJObI7+wyaWf9iIYbniuEXAU5m1kMuKu
         noJyiS4ACO4+1o+vebp2yKsOp5KXaHvPcuT3VuI1/glgVZu6b7g8y7e8FqvF7XBa7c8X
         6KmzNhCQJ0M1E68N9Qtk+yL6EyY7Z4fRasdK/jAOMX7RnZIzsZTbqKrHdHrS8b38tyiq
         pSTK5OMs56VkqasapGN/2YBZveuSewy4N1H7EiqbEMkA4tEAeErvybYv3iBGkA+eTI2h
         4Ibg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:date:cc:to:from
         :subject:message-id;
        bh=KpaiZB0rx3gf50T4gygaQ4EouYDydfmvVdv0TdFqbrQ=;
        b=fyzJfJpzBYmNyuhQ1fqm85tj2ArYQUmo15CbOQj5L5E1ZhhIRn2PXyArfRLsQNS0M9
         DPGU6HIpRL0xb5dNwF4vdh908+Z3HKIp3swxtGXTnpfBM3kXRcZ4JtkyLBHMEiOwgZss
         8Ba2FvPpmq5cDipxfGUhbh2ZcizsvhnnxRwYghXxuwPt0nXRvxQoe9OsPD+UVvBPh5yA
         aVQT7UrUKyIQDa5hSK4eOgAVVwHtA2ajV6I85Y1U8gvfeMVSTWYFNMhNSmsP0tg2jees
         OxRvVAqlpEC+LAivXcP8vmAE71kUvqWY71HCSy1doRxgNA0SAubZVSIlYiqhnsft66xN
         mIAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.249 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Received: from smtprelay.hostedemail.com (smtprelay0249.hostedemail.com. [216.40.44.249])
        by gmr-mx.google.com with ESMTPS id n185si129719oih.3.2020.10.21.11.58.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Oct 2020 11:58:30 -0700 (PDT)
Received-SPF: neutral (google.com: 216.40.44.249 is neither permitted nor denied by best guess record for domain of joe@perches.com) client-ip=216.40.44.249;
Received: from filter.hostedemail.com (clb03-v110.bra.tucows.net [216.40.38.60])
	by smtprelay06.hostedemail.com (Postfix) with ESMTP id A8D79182251B0;
	Wed, 21 Oct 2020 18:58:29 +0000 (UTC)
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Spam-Summary: 50,0,0,,d41d8cd98f00b204,joe@perches.com,,RULES_HIT:1:2:41:334:355:368:369:379:800:960:967:968:973:982:988:989:1260:1277:1311:1313:1314:1345:1437:1515:1516:1518:1593:1594:1605:1730:1747:1777:1792:1801:1981:2194:2199:2393:2525:2566:2682:2685:2828:2859:2933:2937:2939:2942:2945:2947:2951:2954:3022:3138:3139:3140:3141:3142:3865:3866:3867:3868:3870:3871:3874:3934:3936:3938:3941:3944:3947:3950:3953:3956:3959:4052:4250:4321:4419:4605:5007:6737:7904:8603:8985:9025:9149:10004:11026:11232:11473:11657:11658:11914:12043:12048:12296:12297:12438:12555:12760:12986:13018:13019:13161:13229:13439:13972:14394:14659:21080:21433:21451:21627:21811:30029:30054:30089,0,RBL:none,CacheIP:none,Bayesian:0.5,0.5,0.5,Netcheck:none,DomainCache:0,MSF:not bulk,SPF:,MSBL:0,DNSBL:none,Custom_rules:0:0:0,LFtime:1,LUA_SUMMARY:none
X-HE-Tag: iron27_5f08f7c2724a
X-Filterd-Recvd-Size: 10914
Received: from XPS-9350.home (unknown [47.151.133.149])
	(Authenticated sender: joe@perches.com)
	by omf07.hostedemail.com (Postfix) with ESMTPA;
	Wed, 21 Oct 2020 18:58:26 +0000 (UTC)
Message-ID: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
Subject: [PATCH -next] treewide: Remove stringification from __alias macro
 definition
From: Joe Perches <joe@perches.com>
To: Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>, 
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Ard Biesheuvel
 <ardb@kernel.org>,  Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, Marco
 Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Herbert Xu
 <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
 <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, Nick
 Desaulniers <ndesaulniers@google.com>
Cc: linux-kernel@vger.kernel.org, linux-efi@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, linux-mm
	 <linux-mm@kvack.org>
Date: Wed, 21 Oct 2020 11:58:25 -0700
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.36.4-0ubuntu1
MIME-Version: 1.0
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 216.40.44.249 is neither permitted nor denied by best guess
 record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Like the __section macro, the __alias macro uses
macro # stringification to create quotes around
the section name used in the __attribute__.

Remove the stringification and add quotes or a
stringification to the uses instead.

Signed-off-by: Joe Perches <joe@perches.com>
---

There is a script that might eventually be applied
to convert the __section macro definition and uses
to remove stringification

https://lore.kernel.org/lkml/46f69161e60b802488ba8c8f3f8bbf922aa3b49b.camel@perches.com/
https://lore.kernel.org/lkml/75393e5ddc272dc7403de74d645e6c6e0f4e70eb.camel@perches.com/

This patch is intended to create commonality
between the uses of __section and __alias.

 arch/x86/boot/compressed/string.c       |  6 +++---
 arch/x86/include/asm/syscall_wrapper.h  |  2 +-
 drivers/firmware/efi/runtime-wrappers.c |  2 +-
 include/linux/compiler_attributes.h     |  2 +-
 kernel/kcsan/core.c                     | 10 +++++-----
 lib/crc32.c                             |  4 ++--
 lib/crypto/aes.c                        |  4 ++--
 mm/kasan/generic.c                      |  8 ++++----
 8 files changed, 19 insertions(+), 19 deletions(-)

diff --git a/arch/x86/boot/compressed/string.c b/arch/x86/boot/compressed/string.c
index 81fc1eaa3229..d38b122f51ef 100644
--- a/arch/x86/boot/compressed/string.c
+++ b/arch/x86/boot/compressed/string.c
@@ -75,7 +75,7 @@ void *memcpy(void *dest, const void *src, size_t n)
 }
 
 #ifdef CONFIG_KASAN
-extern void *__memset(void *s, int c, size_t n) __alias(memset);
-extern void *__memmove(void *dest, const void *src, size_t n) __alias(memmove);
-extern void *__memcpy(void *dest, const void *src, size_t n) __alias(memcpy);
+extern void *__memset(void *s, int c, size_t n) __alias("memset");
+extern void *__memmove(void *dest, const void *src, size_t n) __alias("memmove");
+extern void *__memcpy(void *dest, const void *src, size_t n) __alias("memcpy");
 #endif
diff --git a/arch/x86/include/asm/syscall_wrapper.h b/arch/x86/include/asm/syscall_wrapper.h
index a84333adeef2..f19d1bbbff3d 100644
--- a/arch/x86/include/asm/syscall_wrapper.h
+++ b/arch/x86/include/asm/syscall_wrapper.h
@@ -69,7 +69,7 @@ extern long __ia32_sys_ni_syscall(const struct pt_regs *regs);
 	long __##abi##_##name(const struct pt_regs *regs);		\
 	ALLOW_ERROR_INJECTION(__##abi##_##name, ERRNO);			\
 	long __##abi##_##name(const struct pt_regs *regs)		\
-		__alias(__do_##name);
+		__alias("__do_" #name);
 
 #define __SYS_STUBx(abi, name, ...)					\
 	long __##abi##_##name(const struct pt_regs *regs);		\
diff --git a/drivers/firmware/efi/runtime-wrappers.c b/drivers/firmware/efi/runtime-wrappers.c
index 1410beaef5c3..14e380ac65d4 100644
--- a/drivers/firmware/efi/runtime-wrappers.c
+++ b/drivers/firmware/efi/runtime-wrappers.c
@@ -162,7 +162,7 @@ static DEFINE_SEMAPHORE(efi_runtime_lock);
  * Expose the EFI runtime lock to the UV platform
  */
 #ifdef CONFIG_X86_UV
-extern struct semaphore __efi_uv_runtime_lock __alias(efi_runtime_lock);
+extern struct semaphore __efi_uv_runtime_lock __alias("efi_runtime_lock");
 #endif
 
 /*
diff --git a/include/linux/compiler_attributes.h b/include/linux/compiler_attributes.h
index ea7b756b1c8f..4819512c9abd 100644
--- a/include/linux/compiler_attributes.h
+++ b/include/linux/compiler_attributes.h
@@ -42,7 +42,7 @@
 /*
  *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-alias-function-attribute
  */
-#define __alias(symbol)                 __attribute__((__alias__(#symbol)))
+#define __alias(symbol)                 __attribute__((__alias__(symbol)))
 
 /*
  *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-aligned-function-attribute
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 3994a217bde7..465f6cfc317c 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -814,7 +814,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
 	}                                                                      \
 	EXPORT_SYMBOL(__tsan_read##size);                                      \
 	void __tsan_unaligned_read##size(void *ptr)                            \
-		__alias(__tsan_read##size);                                    \
+		__alias("__tsan_read" #size);                                  \
 	EXPORT_SYMBOL(__tsan_unaligned_read##size);                            \
 	void __tsan_write##size(void *ptr);                                    \
 	void __tsan_write##size(void *ptr)                                     \
@@ -823,7 +823,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
 	}                                                                      \
 	EXPORT_SYMBOL(__tsan_write##size);                                     \
 	void __tsan_unaligned_write##size(void *ptr)                           \
-		__alias(__tsan_write##size);                                   \
+		__alias("__tsan_write" #size);                                 \
 	EXPORT_SYMBOL(__tsan_unaligned_write##size);                           \
 	void __tsan_read_write##size(void *ptr);                               \
 	void __tsan_read_write##size(void *ptr)                                \
@@ -833,7 +833,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
 	}                                                                      \
 	EXPORT_SYMBOL(__tsan_read_write##size);                                \
 	void __tsan_unaligned_read_write##size(void *ptr)                      \
-		__alias(__tsan_read_write##size);                              \
+		__alias("__tsan_read_write" #size);                            \
 	EXPORT_SYMBOL(__tsan_unaligned_read_write##size)
 
 DEFINE_TSAN_READ_WRITE(1);
@@ -877,7 +877,7 @@ EXPORT_SYMBOL(__tsan_write_range);
 	}                                                                      \
 	EXPORT_SYMBOL(__tsan_volatile_read##size);                             \
 	void __tsan_unaligned_volatile_read##size(void *ptr)                   \
-		__alias(__tsan_volatile_read##size);                           \
+		__alias("__tsan_volatile_read" #size);                         \
 	EXPORT_SYMBOL(__tsan_unaligned_volatile_read##size);                   \
 	void __tsan_volatile_write##size(void *ptr);                           \
 	void __tsan_volatile_write##size(void *ptr)                            \
@@ -892,7 +892,7 @@ EXPORT_SYMBOL(__tsan_write_range);
 	}                                                                      \
 	EXPORT_SYMBOL(__tsan_volatile_write##size);                            \
 	void __tsan_unaligned_volatile_write##size(void *ptr)                  \
-		__alias(__tsan_volatile_write##size);                          \
+		__alias("__tsan_volatile_write" #size);                        \
 	EXPORT_SYMBOL(__tsan_unaligned_volatile_write##size)
 
 DEFINE_TSAN_VOLATILE_READ_WRITE(1);
diff --git a/lib/crc32.c b/lib/crc32.c
index 2a68dfd3b96c..373a17aaa432 100644
--- a/lib/crc32.c
+++ b/lib/crc32.c
@@ -206,8 +206,8 @@ u32 __pure __weak __crc32c_le(u32 crc, unsigned char const *p, size_t len)
 EXPORT_SYMBOL(crc32_le);
 EXPORT_SYMBOL(__crc32c_le);
 
-u32 __pure crc32_le_base(u32, unsigned char const *, size_t) __alias(crc32_le);
-u32 __pure __crc32c_le_base(u32, unsigned char const *, size_t) __alias(__crc32c_le);
+u32 __pure crc32_le_base(u32, unsigned char const *, size_t) __alias("crc32_le");
+u32 __pure __crc32c_le_base(u32, unsigned char const *, size_t) __alias("__crc32c_le");
 
 /*
  * This multiplies the polynomials x and y modulo the given modulus.
diff --git a/lib/crypto/aes.c b/lib/crypto/aes.c
index 827fe89922ff..5b80514595c2 100644
--- a/lib/crypto/aes.c
+++ b/lib/crypto/aes.c
@@ -82,8 +82,8 @@ static volatile const u8 __cacheline_aligned aes_inv_sbox[] = {
 	0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
 };
 
-extern const u8 crypto_aes_sbox[256] __alias(aes_sbox);
-extern const u8 crypto_aes_inv_sbox[256] __alias(aes_inv_sbox);
+extern const u8 crypto_aes_sbox[256] __alias("aes_sbox");
+extern const u8 crypto_aes_inv_sbox[256] __alias("aes_inv_sbox");
 
 EXPORT_SYMBOL(crypto_aes_sbox);
 EXPORT_SYMBOL(crypto_aes_inv_sbox);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 248264b9cb76..4496f897e4f5 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -234,7 +234,7 @@ EXPORT_SYMBOL(__asan_unregister_globals);
 		check_memory_region_inline(addr, size, false, _RET_IP_);\
 	}								\
 	EXPORT_SYMBOL(__asan_load##size);				\
-	__alias(__asan_load##size)					\
+	__alias("__asan_load" #size)					\
 	void __asan_load##size##_noabort(unsigned long);		\
 	EXPORT_SYMBOL(__asan_load##size##_noabort);			\
 	void __asan_store##size(unsigned long addr)			\
@@ -242,7 +242,7 @@ EXPORT_SYMBOL(__asan_unregister_globals);
 		check_memory_region_inline(addr, size, true, _RET_IP_);	\
 	}								\
 	EXPORT_SYMBOL(__asan_store##size);				\
-	__alias(__asan_store##size)					\
+	__alias("__asan_store" #size)					\
 	void __asan_store##size##_noabort(unsigned long);		\
 	EXPORT_SYMBOL(__asan_store##size##_noabort)
 
@@ -258,7 +258,7 @@ void __asan_loadN(unsigned long addr, size_t size)
 }
 EXPORT_SYMBOL(__asan_loadN);
 
-__alias(__asan_loadN)
+__alias("__asan_loadN")
 void __asan_loadN_noabort(unsigned long, size_t);
 EXPORT_SYMBOL(__asan_loadN_noabort);
 
@@ -268,7 +268,7 @@ void __asan_storeN(unsigned long addr, size_t size)
 }
 EXPORT_SYMBOL(__asan_storeN);
 
-__alias(__asan_storeN)
+__alias("__asan_storeN")
 void __asan_storeN_noabort(unsigned long, size_t);
 EXPORT_SYMBOL(__asan_storeN_noabort);
 




-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel%40perches.com.
