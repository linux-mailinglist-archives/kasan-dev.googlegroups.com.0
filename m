Return-Path: <kasan-dev+bncBDY3NC743AGBB64G536AKGQEH3SZBQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7312029FC02
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 04:07:40 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id a184sf4865511ybg.10
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:07:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604027259; cv=pass;
        d=google.com; s=arc-20160816;
        b=y8rRNkf7a8DtZIQV8SCs/+xVGWf2HU4w10uP3Hk9w4xXNor935gYCtFczfoKty2a0+
         EMmPSMS8aWHf+Ytk9Jnk6jUSvxmT9RtbVWVtRiwSJ58cxm69NFRFqWAaQEPG3/729Odk
         24gcfmJk0cptePIiTujhtEcNRsYirGdab1hrXfxwL9qObOKF00CMDFYopkkqFigtUltk
         +NIIhTwmCY6coSAYGelDCR0h1AtWdsON4eMvS6tYcXl+eSK5KZHtI8UQ3bo/EXuXhO7W
         gKSfds2xJKXKdp1Zf6QTF3WwSuGJl2N70dyn7+oZPCNaXspk126ShJp90vUFKI3BHoIr
         OfyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZSmwBHudrfwP/RikTyWUtNzT1mDB3dU1GQWWkmC7a9o=;
        b=Yx0duF/6h1uNF+21/nJechlcHhwMZ4O7KlzQkP8qf37p7KEFbTBVCCUmE5hiEw5L10
         9qZo0yJLQlqpbTM/aXbQQuopzMp6CcBfGPJblBobDVuet/KG98NTQK9wc3qVOBQKyjs4
         uhuIl3Cr0BQpKS+s7zgYiHOgj3a8yXrKUL7RGk2FbMNr+PZJB72bnc2pbP6R6vh3MRub
         P0EuitLwauefyz3gbdJmOrW53je+MKNEthdLy2at7c87BB8gZiFuxc72KFIhSskMcf32
         /SM91jMpsQFfi8tciJ1Q6nrCOrdl9NiFpEryKhTaKuJ5Q+wQa6aUCdLVG+njmwbaYY2h
         j0Jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.81 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZSmwBHudrfwP/RikTyWUtNzT1mDB3dU1GQWWkmC7a9o=;
        b=bD2vIOG2/JqKe0yR0c7RA0Y62uHA/Zivo7K4ZfVJHaKvHZc/bj9lWfmaewg5I3MGKa
         WrKsCRHRM2obTaw73Szw0q6N6N9rJiFCEm7ORS4mNoFDs0En5Y1SOSAZxRjykGgHN7kf
         8zGz+A0xI8RFEIW70g3wGkAbrZFZOyRbCB/dZChf2jTXK/ly2YNVYBzeJ2HyCbSmL2iV
         qFinaBETbRporujs2+SuwZBRD6n59ZiMoMrTvhCf7f5CUqflCjp62Qu4UA1FEhE+f4TV
         HooCl5tkV6oWH0Bs2De6uN1CM4h2eI2rIIOqkuG+Q+wKUFuVLzwGGykslXtKAdDNYt9z
         wakw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZSmwBHudrfwP/RikTyWUtNzT1mDB3dU1GQWWkmC7a9o=;
        b=pDqVngRnssoELnG82atbPwlhugbGLgx4rHMLmjvf93PC4cti/VV29niCL2zQbWPRRx
         K77+BB62lPJuOjwxcH/q5iIE9XpbeL3NOH+23izpsYpMGaRIUALP7GZ0v3VzO+ZnbYEb
         s2LPNelyxN7SMvX6VYn9+pIcBkiF1r/dSoV2qow4ufWMk+3Snf+6c8a8o6cP/HSWCWT9
         uows9oZ1lhV+V2WmpyLeCRHA5BQ8JC1enYXgOCHOmTtOWJLwJ1LN7U93hNwTXczP07WA
         6nNgo8wDwABBn2+OwgIFs2LyCDweuBivPq1HFDkr97uT3ZTu6z9Vfm+lltjgFcunjRlo
         MsyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JsEyJ9deg6C4R+bHfW+LRevkzK7/F6c6C6p8NrQkPoVQJZJ41
	yc5KQZuAjZPDExW/TqLqgrc=
X-Google-Smtp-Source: ABdhPJxCA8J1y+SidkkDd3VQPkMklzjkYA/uQqUUmeTwQu0Yu+Q21axbH/Ngb0MWe/bjuqMk7bX4KQ==
X-Received: by 2002:a25:e6d7:: with SMTP id d206mr762714ybh.144.1604027259343;
        Thu, 29 Oct 2020 20:07:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:df0d:: with SMTP id w13ls2254408ybg.11.gmail; Thu, 29
 Oct 2020 20:07:38 -0700 (PDT)
X-Received: by 2002:a25:2d6e:: with SMTP id s46mr741812ybe.434.1604027258669;
        Thu, 29 Oct 2020 20:07:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604027258; cv=none;
        d=google.com; s=arc-20160816;
        b=gdIk8EPLwgPQjZZQw88YsuMExLVnCYCVWdb8h96ttRvurFDbGpxfIYAzUeP+rkkjIr
         yaeYIzyWhFsYhpXSMGemldb3+hBL7Zt1fV+mjBIGw0AW/j4zOjZCs57Bkw29ZsUwrVyu
         0SugsEZfV38vbCz1hGX48VMusuj6sL8R52JxIML3hrhiBDxnwcL9t3wPXA5Id4Fog2HR
         N9e78FYbuvBN4ijyscFpVXNcRRFfNWK14ymRiWVYiX+ZZ3ztjFhp4jYPqCuGlJDeaKoB
         kg9R+iYU1Ch+2QnpsgDs3P8Ks40BPA1ZaPXNeIgsgTY6/chVEpEVoutwmKiuRd2FHwEK
         VtkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=kOW07ruMgtMSoPFEakK/2W+RKBex0/sPv9DhlIel2Ts=;
        b=bbJC6Qz4+5Z4nEUIC6lAOpi6iUngGdRRbtAtZnTHJIw7aO/MlX6vnDxUZNPdUxWUD1
         KLSwmhJ1ivOZ4hTpURCBnqYXROx/yy8sLkPmfBMEvTKVKLWfAMEXIA6HHokmSnmhuEwt
         E029JGIkCvpBYgKkk2AIk/a4ryU6fbMtQSEJe7R7d7OSQnXv7ui10G/Wg1eccbjGzv4o
         D0FVuhro93xT7mlhHc28Dp5ko7BiG2w4ozrTEB7ctSXCdalQcCcSE2a9TMeEWXBAj8rb
         INXt9uDZrS4UMMeK1Bw5LiBRw7uItR+yPKssuN6pqIXgp3BFz+Ijc6ix21bhMShSjZNx
         Oazg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.81 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Received: from smtprelay.hostedemail.com (smtprelay0081.hostedemail.com. [216.40.44.81])
        by gmr-mx.google.com with ESMTPS id e184si224063ybe.0.2020.10.29.20.07.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Oct 2020 20:07:38 -0700 (PDT)
Received-SPF: neutral (google.com: 216.40.44.81 is neither permitted nor denied by best guess record for domain of joe@perches.com) client-ip=216.40.44.81;
Received: from filter.hostedemail.com (clb03-v110.bra.tucows.net [216.40.38.60])
	by smtprelay02.hostedemail.com (Postfix) with ESMTP id DD427629;
	Fri, 30 Oct 2020 03:07:37 +0000 (UTC)
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Spam-Summary: 50,0,0,,d41d8cd98f00b204,joe@perches.com,,RULES_HIT:1:2:41:334:355:368:369:379:541:800:960:967:968:973:988:989:1260:1311:1314:1345:1437:1515:1605:1730:1747:1777:1792:1801:1981:2194:2198:2199:2200:2393:2525:2561:2564:2682:2685:2859:2933:2937:2939:2942:2945:2947:2951:2954:3022:3138:3139:3140:3141:3142:3865:3866:3867:3868:3870:3872:3934:3936:3938:3941:3944:3947:3950:3953:3956:3959:4052:4250:4321:4419:4605:5007:6119:6261:6691:6737:6742:7903:7904:8603:9025:9149:10004:10848:11026:11232:11473:11657:11658:11914:12043:12048:12296:12297:12438:12555:12895:12986:13894:13972:14394:21080:21433:21451:21627:30029:30054:30089,0,RBL:none,CacheIP:none,Bayesian:0.5,0.5,0.5,Netcheck:none,DomainCache:0,MSF:not bulk,SPF:,MSBL:0,DNSBL:none,Custom_rules:0:0:0,LFtime:1,LUA_SUMMARY:none
X-HE-Tag: rain79_4f07ec327292
X-Filterd-Recvd-Size: 11188
Received: from joe-laptop.perches.com (unknown [47.151.133.149])
	(Authenticated sender: joe@perches.com)
	by omf13.hostedemail.com (Postfix) with ESMTPA;
	Fri, 30 Oct 2020 03:07:34 +0000 (UTC)
From: Joe Perches <joe@perches.com>
To: Linus Torvalds <torvalds@linux-foundation.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	"David S. Miller" <davem@davemloft.net>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Nathan Chancellor <natechancellor@gmail.com>,
	Nick Desaulniers <ndesaulniers@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-kernel@vger.kernel.org,
	linux-efi@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-mm@kvack.org,
	clang-built-linux@googlegroups.com
Subject: [PATCH] treewide: Remove stringification from __alias macro definition
Date: Thu, 29 Oct 2020 20:07:31 -0700
Message-Id: <8451df41359b52f048780d19e07b6fa4445b6392.1604026698.git.joe@perches.com>
X-Mailer: git-send-email 2.26.0
MIME-Version: 1.0
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 216.40.44.81 is neither permitted nor denied by best guess
 record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Content-Type: text/plain; charset="UTF-8"
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

Like the old __section macro, the __alias macro uses macro # stringification
to create quotes around the symbol name used in the __attribute__.

This can cause differences between gcc and clang when the stringification
itself contains a quote character.  So avoid these differences by always
using quotes to define the aliased symbol.

Remove the stringification and add quotes and when necessary a stringification
when existing uses have a ## concatenation.

Signed-off-by: Joe Perches <joe@perches.com>
---

Unlike the __section macro conversion in commit 33def8498fdd
("treewide: Convert macro and uses of __section(foo) to __section("foo")")
this one was done by hand.

No other use of __alias exists in the kernel.

This patch does _not_ convert any uses of __attribute__((alias("<foo>")))
so it should not cause any compilation issues.

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
2.26.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8451df41359b52f048780d19e07b6fa4445b6392.1604026698.git.joe%40perches.com.
