Return-Path: <kasan-dev+bncBDE6RCFOWIARBR5DSP6AKGQEQVG5EKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id E93AE28C463
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 23:59:35 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id t145sf641189lff.22
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 14:59:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602539975; cv=pass;
        d=google.com; s=arc-20160816;
        b=uWbQZremIArnaKZ3+s/4yjvWrvw/0Gw4Lc84gD4QgvGpTmWnOG81+0kNu9O0iTsZHT
         /uVHCDxR5T1pZqrDHloxjaBcgrfh0eNkXfs9pVvum1EwX/8BIpg5zMyjWG3a8ax/4E7A
         2KVk7PK0UqwrZ+DFM8zPMgXoFXvqq5z/AGNGWW5s/BSecSjpxdBwa5HkeYyNDwnQywj5
         uTF1cifgnCLqf6lwCjFrx9Bgx2BCncsODc+KFiIWjaznR7fZUT8G4wGBLKlXpWuVrazf
         gr4UNIWmWrzQgVZoYTzDXC4xv+q682CY2jDgRki2gmMqX26cX1SWvO/QupiKnIUyq2Qi
         oTBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cioCBes3hN4ITh8dCAajOL7rz1JlZDSHNBa689PrGiU=;
        b=UjekQ5RbdXP03Hisq3GuNzXZ3dR/slwXmoPQXkHKkQqvnCsr+ypslAwvX4+J7BAqAb
         dbp36/dbDd+K6zZDZv2kELY1plYBnEfMBd8MEU64iezg6mqexDmVCfrTC2zTgoIizeR8
         3ZaPF65A7yvTpPe6Af+PIauX8kj7kOrqYDjW4WNGwJtJEBXjYAkcxc91mJ6xckb/Gu7M
         pOEiaxwLKK32ML8UYhsKO89FpreA3437cXn7NPBMRnWT0CQ94Nnrw0H68QFYOZEeFfPU
         APZJoCHC2h3txZGayDH3lLer9LJo52qGkagE7Uz2DySReeWFlqy28ZtOars2yiTjngPz
         VHTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="saXoXe/f";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cioCBes3hN4ITh8dCAajOL7rz1JlZDSHNBa689PrGiU=;
        b=hn7m5Wknkmfy92nSN+0ykwhSBohXmHufqAKATgx6oLWEy1ryHAGkt7mznkZtlotU7o
         IA1a32qoTPCDlUp3ad2vJd4JxynejnB//QyJIhrBsZsZYp5Sqru7zvnTq7WVqvbj8iS8
         HcABBqahPCJDEhBJSTppSPF7VbuYOtAhOuyt2/EMGab5BzeJ/Qok6uNtDe++dkGFi/22
         WFuTUat6WcxZHlXA/WQmkLqVvaGfFqvlgwjEKeRDkJ+jhuXI/edXZrL4cWR4jg1LUfab
         b/iuSDsZfUPtgkp62cnf56Y0O97qDgB2DZU9Ifg/KbLLnd4jv2mvCM30ZgED0s0dS9wI
         Lq7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cioCBes3hN4ITh8dCAajOL7rz1JlZDSHNBa689PrGiU=;
        b=c0y+GY/CPkSVSxoJmPAm9OvXGAzl/vt07DP+ETS3fFHK+5WLz6cWrQYtC4b4GXb22c
         +bLXr1VLcsyC052ltS6nTs/jwdy5BjVHcASn1S9NRQnuDFFs7gfqgLDINsdXQRVlhXT5
         TixQSNMynG/sV/3GNacudMY5NvMPa5AGB9YzVTS7VuwDaQTqMXOkLqWEK0pxJDByCqxv
         op/9QrM/6Ee4DG45bdy2pBvPXEP0nrwSAGnZEqBgKQzx5L8Y0FPM+usgkvph2+261dTw
         hBP9Zkn9wNJZahAefcp+rwLeOmTGyejWz7DG+Y018sfIJkIZtlk2Fd4/PuZCu6k9eiov
         2ZBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531B5+5L+uUuPabV+ts5Qs+kJVsyg24f4WlEmK+e5MrYEJeTGqzf
	dmViJCxSCXOFkBuOfLpamuY=
X-Google-Smtp-Source: ABdhPJxLEDCBz0YGKf3mX2kGRi1YyZhWgTAzSl86C5jD7E7YE5m60Q1xAJC4npkJFyDuuY19ICix/A==
X-Received: by 2002:a05:6512:504:: with SMTP id o4mr7360427lfb.450.1602539975472;
        Mon, 12 Oct 2020 14:59:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ad43:: with SMTP id s3ls915458lfd.2.gmail; Mon, 12 Oct
 2020 14:59:34 -0700 (PDT)
X-Received: by 2002:a19:7009:: with SMTP id h9mr3367820lfc.201.1602539974626;
        Mon, 12 Oct 2020 14:59:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602539974; cv=none;
        d=google.com; s=arc-20160816;
        b=dQDmYOY5xYZ6Q/XApqU6vNhxTl+xhgyqYXI8yZavF8WU4bafkM2rUOu6RafkYN31G8
         qmiSGqCSF7jyvsQpHEwWqsyBstYFtnp7kIN2NMSXi53ye7P2EwvIWhF09fc2Hp7IvS2N
         nnYjC1jPFyTULjGqQ3u4ROSfEnaQUzA7eXuzBQ6XFVo5yTevsOtwb+OWewENxig5MDYb
         IfFY6t4gE1lPF09nez4cL+3cPFI2pLig4XEZZXyHb76lKGmw3M9nleQ8pZfZHXZRNlrc
         yYxXLjygTasuvVbfgFcsKN0oaxdMJ+hhaQ9ehpgepQNog1VxRckzObkZA6AemxqkBUqU
         pBTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=I1HNLzgbgjRpmzvVVujf4EgzKf8qDWdR61GkrHtlcwc=;
        b=Xw4vh1H4GzNA9xykLVW6fghs/d9Ol5lCUZwAb7pNCP/ELNcFcsz/jaZbRwheZWbmFv
         nbI/MxG+qAbeAq+7Q3SGsERl9sPmKILZwzIlm9Sz27TxO03ucE7c5xFD08DcdJh9gHio
         wGDIRuBS64XjLnlBBhfU4UChV/d0Y8MezzkdV9Q7yQHkiuOsi/A6t3P7YyMmSUK5NY02
         m7RQ9AByCSFTnqxC0+Gqx4bQ9VG7fn1W54JhSwkc+8NTl30anwKO3cVz7dNsjdRM73e/
         dnFfle91kA2T0YcBOabhYhEWiIiu2HsGtp0PayoSB/cEFq9Qnm3fnkvsHvx4YZZklBd8
         xkqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="saXoXe/f";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x142.google.com (mail-lf1-x142.google.com. [2a00:1450:4864:20::142])
        by gmr-mx.google.com with ESMTPS id a1si503953lff.2.2020.10.12.14.59.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 14:59:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) client-ip=2a00:1450:4864:20::142;
Received: by mail-lf1-x142.google.com with SMTP id r127so19829651lff.12
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 14:59:34 -0700 (PDT)
X-Received: by 2002:a19:4bc9:: with SMTP id y192mr8266113lfa.447.1602539974332;
        Mon, 12 Oct 2020 14:59:34 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id w9sm2985887ljh.95.2020.10.12.14.59.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Oct 2020 14:59:33 -0700 (PDT)
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
Subject: [PATCH 2/5 v15] ARM: Replace string mem* functions for KASan
Date: Mon, 12 Oct 2020 23:56:58 +0200
Message-Id: <20201012215701.123389-3-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20201012215701.123389-1-linus.walleij@linaro.org>
References: <20201012215701.123389-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="saXoXe/f";       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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
ChangeLog v14->v15:
- Resend with the other patches
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201012215701.123389-3-linus.walleij%40linaro.org.
