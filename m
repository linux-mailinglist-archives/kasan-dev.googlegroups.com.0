Return-Path: <kasan-dev+bncBDE6RCFOWIARBTHI275QKGQEU4TXTUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id F1756280284
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 17:22:52 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id s20sf2036889ejx.19
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 08:22:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601565772; cv=pass;
        d=google.com; s=arc-20160816;
        b=b6qBtjhH+EFbOfg4eVDQI5dhZX/65A5HxKzHrNaedSHxujGjeJxR6xwFzosz33Emnn
         GIBuLJa5Ev0AniODYX4XzbpsyT4OPD8YErQ/4pDzZwr5ripjjxZXNnprT4LchBYphSEb
         xI/yqV73V6Yh+1JXFRuXA2bD6/v349Ohv2kroJx3j1eYguzytQlBzbnnFEA3qTFf+tDu
         1JNMR8Rb9SpMdBxo2kuykOXiPN8U2ZG52NcRP3IEsJBXEflsu8oakeyBm1nT6cYPk5Dn
         xA/VDPzbi5cjI6rDfTYbAD8YGZ26BXTLyORAWSBms8lU49mEkLpBPhFP/638bBfd6XWn
         fpZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PefZXkcMszX3uWAO5Rk82vJwxjPFuuDNfTTplTfgYJY=;
        b=Fx9VaZbbtg7eggXA+Y0XsNBbMMJ810C2ocWFxLTR0ZiTU+mW1N3HGRcQjYm243Wiln
         tgqpr19OkP0daX4+VzSQb1UyX/EhX9TIl2BIfOdUyFz6d6MD4L3ZX1oel8mOC1ht+hmA
         X4j6gsY5sRkxCVfkzgglFGfw0Co0d+omjFiEJFVY4uL7YnKWJLDcBWd8iJW0Hx2kgwmX
         ci0NrH2GE35LnkrZbCjnunhOIe5M7mt0+8GvQk9uR+hK47wyMKCVRcQZX7JLdclVtEIu
         kqxj0y2NtPv0WECXdMq9CqMZqluEyuxwNTKbmrrBRaBd9yjVxFIr7aOmPIbLZGb7lUnR
         SLXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=YJPgOnbJ;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PefZXkcMszX3uWAO5Rk82vJwxjPFuuDNfTTplTfgYJY=;
        b=RHmYXrN9HG++Mklv7VWkFdyvJwoBi7ASSH3M8X6klLnZPOj/dNzP5U/Uwm8Tx5Nsx8
         3kpNM6389x60FkDUs2nsjui6y1Yv8yQIiCaVwFmPOwgazHgtXx1YIMovIodqnLtnQ8LE
         NiSPc/imlv4+zKzFgsQfj15V1iCDnjY5y+kGYnQWgLkd0TLUZW0z3cSDrh0asvqGAO9H
         z5t828d2AUKJLNhXRsDa1BGvQZNRcpWdXKjymZ7f0vx6iMabJlyYq8FM56oMhX2ZutI1
         gEYaEr3uxP9dWEokPXCcC972EP7BNI1mG8nrlyJPipLAt6du/u57KCHQScWkLl1KaGoD
         nLsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PefZXkcMszX3uWAO5Rk82vJwxjPFuuDNfTTplTfgYJY=;
        b=mjgT4uECJG5mMiWkWftjhjNQRp7EpN5FIMhoZC0TkKSIX4AOdLEeQx93qerRmJGAs3
         LtP7z62hFkS6BXWFHswIK3TZtY8977vJayxZSL/GMc+pmzZN81fERuwhxLfeHl+TLq4k
         s1UG4++fGJNRE0nARNYJLA5ptABm8zL2RSUwtJ8Z8IpNpuPS+hiLpcUSsiqgZpls8xRl
         sCxDWEmdXjHHkNcjWvR9hvgXRSHmeySB6DR0R4m+YpcnFTsptjnJkTVJjPQnXMeHvON7
         6FnoY6HOE1s3HWwr63mdDWPE00eIyzn4LqgAhM8FjlnQx+1yNFchRZn8rZPuuLFCCYMz
         FWPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533rBAZ173qB8dR9/RjchG7uDETaIWrApIJxV6xu7NQuovPkxPhB
	OQXz7EI7DTL8WeDgTsUbULg=
X-Google-Smtp-Source: ABdhPJwT26vlDfp02BwHrgRVjVTjVwxm8MuuiJ1YzhSKfMALqV43YQ+bB7YrTKgVKjCquSpuqcamRQ==
X-Received: by 2002:a17:906:1955:: with SMTP id b21mr3094559eje.42.1601565772589;
        Thu, 01 Oct 2020 08:22:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:bf49:: with SMTP id g9ls1720329edk.1.gmail; Thu, 01 Oct
 2020 08:22:51 -0700 (PDT)
X-Received: by 2002:a05:6402:1602:: with SMTP id f2mr7103894edv.343.1601565771746;
        Thu, 01 Oct 2020 08:22:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601565771; cv=none;
        d=google.com; s=arc-20160816;
        b=IRPBZ93LT6ruPOPkKFctDxAYCEsjBkCtL1KXcvN9IlD9po3UVDuV8350KrZQAS1vZx
         7WjuOSJ2GpFUmasntyJM3+XeODpc4pbZelVoLAUenjiRTJgnCajTlkQ6MatQSINWxEUI
         NWURtEH60j5VI/gdY7WphfwwOtztuWW7veLpovsaNe+2gBxOiTQAAPnnNZKEGOBIlajU
         Oi+APHZ5qcW0oGb406465X9j/3hHJATuZpcfCfjUmWEWJ4U2Ao7erzf995eDe4STW+sa
         uwSA3MC38+nG7TVYnmb0QzHGbaqmdLzjdINDZ7OP+RcoM0CB+29uqvYWOXZ52HZHsSM6
         uSrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jCHpWVPO4Q52fGGtz9v20WzdlaE038QP3xuRrffiRR0=;
        b=FPFEcWnLvZxLoBfxrF6c5WbTyyNgFYVOeiIZE4sKQHGnOlX1Mhb9Ciepu6g9VxARke
         MDjI6I9iBw2qljWipGX5XFzdAkoC8P2qMsvDO4pxqxmaAikDS+ApT8jeufiElUGj4u/t
         nBJRPA5k2cqa6HZ8GGYcoIFvBqVP6v8SXuufJL+jjVwoRTys6Ffr/FpJNNk+QOlzrUzW
         dgTUfQq46eER06Tgo6WCoa3kQsUc+Lc3UC8OZXGpL1AAV40FtVa8GjVD8jPSJ34cE8uF
         H5rYNi7U3LpPSAfe2wc7dp++tMLwl1sMDRlMOvLgt7I1ANNDdrda6SDKsGp2y3LK84Pn
         Fj7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=YJPgOnbJ;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id f17si149908edx.5.2020.10.01.08.22.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 08:22:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id b22so7034112lfs.13
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 08:22:51 -0700 (PDT)
X-Received: by 2002:a19:c355:: with SMTP id t82mr3050302lff.251.1601565771158;
        Thu, 01 Oct 2020 08:22:51 -0700 (PDT)
Received: from genomnajs.ideon.se ([85.235.10.227])
        by smtp.gmail.com with ESMTPSA id v18sm587578lfa.238.2020.10.01.08.22.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 08:22:50 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Mike Rapoport <rppt@linux.ibm.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 3/6 v14] ARM: Replace string mem* functions for KASan
Date: Thu,  1 Oct 2020 17:22:29 +0200
Message-Id: <20201001152232.274367-4-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20201001152232.274367-1-linus.walleij@linaro.org>
References: <20201001152232.274367-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=YJPgOnbJ;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

From: Andrey Ryabinin <aryabinin@virtuozzo.com>

Functions like memset()/memmove()/memcpy() do a lot of memory
accesses.

If a bad pointer is passed to one of these functions it is important
to catch this. Compiler instrumentation cannot do this since these
functions are written in assembly.

KASan replaces these memory functions with instrumented variants.

The original functions are declared as weak symbols so that
the strong definitions in mm/kasan/kasan.c can replace them.

The original functions have aliases with a '__' prefix in their
name, so we can call the non-instrumented variant if needed.

We must use __memcpy()/__memset() in place of memcpy()/memset()
when we copy .data to RAM and when we clear .bss, because
kasan_early_init cannot be called before the initialization of
.data and .bss.

For the kernel compression and EFI libstub's custom string
libraries we need a special quirk: even if these are built
without KASan enabled, they rely on the global headers for their
custom string libraries, which means that e.g. memcpy()
will be defined to __memcpy() and we get link failures.
Since these implementations are written i C rather than
assembly we use e.g. __alias(memcpy) to redirected any
users back to the local implementation.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v13->v14:
- Resend with the other patches
ChangeLog v12->v13:
- Rebase on kernel v5.9-rc1
ChangeLog v11->v12:
- Resend with the other changes.
ChangeLog v10->v11:
- Resend with the other changes.
ChangeLog v9->v10:
- Rebase on v5.8-rc1
ChangeLog v8->v9:
- Collect Ard's tags.
ChangeLog v7->v8:
- Use the less invasive version of handling the global redefines
  of the string functions in the decompressor: __alias() the
  functions locally in the library.
- Put in some more comments so readers of the code knows what
  is going on.
ChangeLog v6->v7:
- Move the hacks around __SANITIZE_ADDRESS__ into this file
- Edit the commit message
- Rebase on the other v2 patches
---
 arch/arm/boot/compressed/string.c | 19 +++++++++++++++++++
 arch/arm/include/asm/string.h     | 21 +++++++++++++++++++++
 arch/arm/kernel/head-common.S     |  4 ++--
 arch/arm/lib/memcpy.S             |  3 +++
 arch/arm/lib/memmove.S            |  5 ++++-
 arch/arm/lib/memset.S             |  3 +++
 6 files changed, 52 insertions(+), 3 deletions(-)

diff --git a/arch/arm/boot/compressed/string.c b/arch/arm/boot/compressed/string.c
index ade5079bebbf..8c0fa276d994 100644
--- a/arch/arm/boot/compressed/string.c
+++ b/arch/arm/boot/compressed/string.c
@@ -7,6 +7,25 @@
 
 #include <linux/string.h>
 
+/*
+ * The decompressor is built without KASan but uses the same redirects as the
+ * rest of the kernel when CONFIG_KASAN is enabled, defining e.g. memcpy()
+ * to __memcpy() but since we are not linking with the main kernel string
+ * library in the decompressor, that will lead to link failures.
+ *
+ * Undefine KASan's versions, define the wrapped functions and alias them to
+ * the right names so that when e.g. __memcpy() appear in the code, it will
+ * still be linked to this local version of memcpy().
+ */
+#ifdef CONFIG_KASAN
+#undef memcpy
+#undef memmove
+#undef memset
+void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias(memcpy);
+void *__memmove(void *__dest, __const void *__src, size_t count) __alias(memmove);
+void *__memset(void *s, int c, size_t count) __alias(memset);
+#endif
+
 void *memcpy(void *__dest, __const void *__src, size_t __n)
 {
 	int i = 0;
diff --git a/arch/arm/include/asm/string.h b/arch/arm/include/asm/string.h
index 111a1d8a41dd..947f93037d87 100644
--- a/arch/arm/include/asm/string.h
+++ b/arch/arm/include/asm/string.h
@@ -5,6 +5,9 @@
 /*
  * We don't do inline string functions, since the
  * optimised inline asm versions are not small.
+ *
+ * The __underscore versions of some functions are for KASan to be able
+ * to replace them with instrumented versions.
  */
 
 #define __HAVE_ARCH_STRRCHR
@@ -15,15 +18,18 @@ extern char * strchr(const char * s, int c);
 
 #define __HAVE_ARCH_MEMCPY
 extern void * memcpy(void *, const void *, __kernel_size_t);
+extern void *__memcpy(void *dest, const void *src, __kernel_size_t n);
 
 #define __HAVE_ARCH_MEMMOVE
 extern void * memmove(void *, const void *, __kernel_size_t);
+extern void *__memmove(void *dest, const void *src, __kernel_size_t n);
 
 #define __HAVE_ARCH_MEMCHR
 extern void * memchr(const void *, int, __kernel_size_t);
 
 #define __HAVE_ARCH_MEMSET
 extern void * memset(void *, int, __kernel_size_t);
+extern void *__memset(void *s, int c, __kernel_size_t n);
 
 #define __HAVE_ARCH_MEMSET32
 extern void *__memset32(uint32_t *, uint32_t v, __kernel_size_t);
@@ -39,4 +45,19 @@ static inline void *memset64(uint64_t *p, uint64_t v, __kernel_size_t n)
 	return __memset64(p, v, n * 8, v >> 32);
 }
 
+/*
+ * For files that are not instrumented (e.g. mm/slub.c) we
+ * must use non-instrumented versions of the mem*
+ * functions named __memcpy() etc. All such kernel code has
+ * been tagged with KASAN_SANITIZE_file.o = n, which means
+ * that the address sanitization argument isn't passed to the
+ * compiler, and __SANITIZE_ADDRESS__ is not set. As a result
+ * these defines kick in.
+ */
+#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
+#define memcpy(dst, src, len) __memcpy(dst, src, len)
+#define memmove(dst, src, len) __memmove(dst, src, len)
+#define memset(s, c, n) __memset(s, c, n)
+#endif
+
 #endif
diff --git a/arch/arm/kernel/head-common.S b/arch/arm/kernel/head-common.S
index 4a3982812a40..6840c7c60a85 100644
--- a/arch/arm/kernel/head-common.S
+++ b/arch/arm/kernel/head-common.S
@@ -95,7 +95,7 @@ __mmap_switched:
  THUMB(	ldmia	r4!, {r0, r1, r2, r3} )
  THUMB(	mov	sp, r3 )
 	sub	r2, r2, r1
-	bl	memcpy				@ copy .data to RAM
+	bl	__memcpy			@ copy .data to RAM
 #endif
 
    ARM(	ldmia	r4!, {r0, r1, sp} )
@@ -103,7 +103,7 @@ __mmap_switched:
  THUMB(	mov	sp, r3 )
 	sub	r2, r1, r0
 	mov	r1, #0
-	bl	memset				@ clear .bss
+	bl	__memset			@ clear .bss
 
 	ldmia	r4, {r0, r1, r2, r3}
 	str	r9, [r0]			@ Save processor ID
diff --git a/arch/arm/lib/memcpy.S b/arch/arm/lib/memcpy.S
index 09a333153dc6..ad4625d16e11 100644
--- a/arch/arm/lib/memcpy.S
+++ b/arch/arm/lib/memcpy.S
@@ -58,6 +58,8 @@
 
 /* Prototype: void *memcpy(void *dest, const void *src, size_t n); */
 
+.weak memcpy
+ENTRY(__memcpy)
 ENTRY(mmiocpy)
 ENTRY(memcpy)
 
@@ -65,3 +67,4 @@ ENTRY(memcpy)
 
 ENDPROC(memcpy)
 ENDPROC(mmiocpy)
+ENDPROC(__memcpy)
diff --git a/arch/arm/lib/memmove.S b/arch/arm/lib/memmove.S
index b50e5770fb44..fd123ea5a5a4 100644
--- a/arch/arm/lib/memmove.S
+++ b/arch/arm/lib/memmove.S
@@ -24,12 +24,14 @@
  * occurring in the opposite direction.
  */
 
+.weak memmove
+ENTRY(__memmove)
 ENTRY(memmove)
 	UNWIND(	.fnstart			)
 
 		subs	ip, r0, r1
 		cmphi	r2, ip
-		bls	memcpy
+		bls	__memcpy
 
 		stmfd	sp!, {r0, r4, lr}
 	UNWIND(	.fnend				)
@@ -222,3 +224,4 @@ ENTRY(memmove)
 18:		backward_copy_shift	push=24	pull=8
 
 ENDPROC(memmove)
+ENDPROC(__memmove)
diff --git a/arch/arm/lib/memset.S b/arch/arm/lib/memset.S
index 6ca4535c47fb..0e7ff0423f50 100644
--- a/arch/arm/lib/memset.S
+++ b/arch/arm/lib/memset.S
@@ -13,6 +13,8 @@
 	.text
 	.align	5
 
+.weak memset
+ENTRY(__memset)
 ENTRY(mmioset)
 ENTRY(memset)
 UNWIND( .fnstart         )
@@ -132,6 +134,7 @@ UNWIND( .fnstart            )
 UNWIND( .fnend   )
 ENDPROC(memset)
 ENDPROC(mmioset)
+ENDPROC(__memset)
 
 ENTRY(__memset32)
 UNWIND( .fnstart         )
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001152232.274367-4-linus.walleij%40linaro.org.
