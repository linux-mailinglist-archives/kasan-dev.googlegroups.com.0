Return-Path: <kasan-dev+bncBCJMBM5G5UCRBEWB6CNQMGQEWIEWFPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E1DC6331DB
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 02:06:28 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id n8-20020a6b4108000000b006de520dc5c9sf6355755ioa.19
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 17:06:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669079187; cv=pass;
        d=google.com; s=arc-20160816;
        b=b6DGBkGX3L0N4ppPxeZ4otOCQZlnaIaibvmcuwKXYLB9Kj5ApI2Yuom1RXek0okUER
         Uqxoe1IaI848qB96Glq7fLZ+K2erZQr+7Ag5FQlDi1tNS57QDXdHWmDmVO9mQnpxo1Wn
         5rK4B7dREROZXonOQKyLqwDDWhS8Eb689W2ZNPxYzyuOzgYufYqMbSJLPBgIwlOZBN2X
         W9xAcjDIACR1NKaOECArxKsGY/RGsfZwgOXdhQH0T6kQEpwiEeQT1ZZNx/7RB4LkIC7i
         DSKTSHctKL6J6BqHiM3dnjRTq7yaZyOARB1IExKiO+myB49As9ly9qQyKbD5qOLWb4bV
         SZUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=9jvpN3KhlqfSOF++XQ0h0hehffh+s7Z6c2nZhaNxz5I=;
        b=ZizucR2N4FjhGIhBBL2V6XjFKxP01SjXYyfCKlgOo6dv9PYQgY/xmf+IDGgih0Mmp6
         IzoP71fa+nn9hHujMLFcvKVa2I0wpAEYuBn0zXDA9fYvwX9A862aa1eRb54u6xzJI/w6
         1Wks9svtElvzvcE9mIV21HeXGYZMu3Qz9pDn4abccCEKnl7Jr/fSpqSIqdnikNw03Xm3
         tTbeVR6TSHicMrdff/N03x49HwFkuU5Gjzx8KrCgCtmcs0fKRMCwU+nA0vavmmhIpuYt
         F+fB5uPZ6fh7SgBhyLvvsoB+IlAi5JqvIw0a88zeepfnr+oYpga7c1DK3K3k0CCVBYUd
         7NLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=m7Nka8d6;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=BfX3WKZh;
       spf=pass (google.com: domain of 010101849cdf36fd-b21db532-45fc-4c27-a53d-9194640eb608-000000@us-west-2.amazonses.com designates 54.240.27.18 as permitted sender) smtp.mailfrom=010101849cdf36fd-b21db532-45fc-4c27-a53d-9194640eb608-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9jvpN3KhlqfSOF++XQ0h0hehffh+s7Z6c2nZhaNxz5I=;
        b=T1KSM4m18/wNYZLd5dnmW4itCq5f8jlbLzPGgbSbg7DzTixVv9scGrITn9W3jlNNZa
         PcNsOgktCDqqm4sf/7JGxiiQP9NUYpMNVf34Qwi74VZKuVWAZhl8Pm7vNlDfb6cjkQOY
         6U7pY+NwlxecsH/Rb/F5TFGWLuxm8PXpZrszmhgkR4vucPU1m5/L9JxsBi4oXqp7hZ3i
         qrXoNUp8Vw1WdOi8EvXX2NO+Z4u3EfisG/0DRv9dboRTSwDDC7r9YMikXGgQDYxpXu8R
         DSCRyY+BJccDmCml/9IOi9gkbRG8JnQ+OR7+leVqB6F8zqs765BJpWiOH4GzlVXmcT6F
         lo5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=9jvpN3KhlqfSOF++XQ0h0hehffh+s7Z6c2nZhaNxz5I=;
        b=61Rz6rkHQy9thZxQDv3mW2x1DY7P6cYDiRObZKpyiyV5ds86hDF9MZ67yO2wOLNfIK
         uctDlnVRA9yeGKAQiRMMzv6iSiDQGz6CAkWRcW+97XALXyi6R2f2w0VfECUCMAIARsgw
         8Kz0tDAkWJ7kdvBFt3nHj/hP2Z3UxfiV9OZ0j1DqdUnNKtJt33Mw+uO3x3WMtg/Mgycr
         rwzrVvEkGbmtMfi0OLRcf2RSenSY5OWhkzo/PJMb1PvyEivibLXer5BAHozwWMNX6q7k
         M9Yfl8nWZom5rG4D5YQ1EDTARwaitBwZwnE9NH+jMcI/rMPtpYGSVKhnyxAj8COySUSX
         z7wQ==
X-Gm-Message-State: ANoB5pmSYKU88cM/UhzH8PtofAmRdJ+KjVSJ2o/YeAD8Qi2p4UA8cImI
	DkE9s6L48jA02KqnxRoLI6I=
X-Google-Smtp-Source: AA0mqf5UV5dfD3silvhON/Oqioox/oXCpWXxQJCJJ346/hNlu28niFj/q0XtUO0ZP5OZjPRuW3xK4g==
X-Received: by 2002:a05:6602:378f:b0:6db:7942:d64a with SMTP id be15-20020a056602378f00b006db7942d64amr2600537iob.198.1669079186837;
        Mon, 21 Nov 2022 17:06:26 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:11b4:b0:302:c628:d794 with SMTP id
 20-20020a056e0211b400b00302c628d794ls612801ilj.2.-pod-prod-gmail; Mon, 21 Nov
 2022 17:06:26 -0800 (PST)
X-Received: by 2002:a92:cd51:0:b0:302:a5a8:5296 with SMTP id v17-20020a92cd51000000b00302a5a85296mr4128449ilq.228.1669079186341;
        Mon, 21 Nov 2022 17:06:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669079186; cv=none;
        d=google.com; s=arc-20160816;
        b=Gid7urs0MbYB91eJbcdGMAy9t6K7+DusqNfp6Sdj+A6iRV6/sJIG0nTg0J9Hx12Ht6
         kSdWM3IMIINVzDpwhhyzMcTZrnx+coU6YdCzhK0bkWfdTn5y/q9Tmx8yaepnBiCEzFoP
         A4xkcN7p0/roNf9eAXUuw+HpeK0IQnjFn4HK8ne9KVaHXcPSIxeFwO3R2TU1khC1wmC4
         gWZUOHQcKuq5hiwZPbhSVcOHSgvnJNUWLZkNQ5/NEJ46o3FefnEcceGdEEVXTkzQJ/mc
         P3PqHkIoTwxt0wyHGLFIpJbK4w4RMLI6dcmG1MYBxN14xAL8EZI6CY7KFXE0SXUnZxLu
         X9YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=cpTXJxN8elW3Ly39fLtiy4rWTPnfTswoJOmZeOnwRDM=;
        b=RzQefoyaf1xr3oS6MHAg3js1eLkebXZfURqpInRLTs6S96MYTr5sZr1+1kiKfFNyuf
         lDcphNl/SZSe3mUrhHUac++0LbylpyMpdVs/j7GXrdaa5rKgwp7LQB6szkDnMM4WXhHH
         nrxqDEnvTl1NQ25A+itri7pkUX1ZkEF1UEHQ59zCKu1+ZYLhCoToHcpWoSKxlyEkuES9
         fEb41T0NK/jK8WuC12kdFoIZs4zQN6U5dQsXV6dvZ2hIlZCFg6MF+eZPhMHEPRDyV0bo
         iGGDl7B9NBMnsi1YNO1snZwT8dBaSA+CKI8CbG2dpMCjWQ9Y8x8Nu2L5g/pifjX0hnWc
         Cs8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=m7Nka8d6;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=BfX3WKZh;
       spf=pass (google.com: domain of 010101849cdf36fd-b21db532-45fc-4c27-a53d-9194640eb608-000000@us-west-2.amazonses.com designates 54.240.27.18 as permitted sender) smtp.mailfrom=010101849cdf36fd-b21db532-45fc-4c27-a53d-9194640eb608-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-18.smtp-out.us-west-2.amazonses.com (a27-18.smtp-out.us-west-2.amazonses.com. [54.240.27.18])
        by gmr-mx.google.com with ESMTPS id x12-20020a5d990c000000b006a128dbb6efsi643930iol.0.2022.11.21.17.06.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 17:06:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 010101849cdf36fd-b21db532-45fc-4c27-a53d-9194640eb608-000000@us-west-2.amazonses.com designates 54.240.27.18 as permitted sender) client-ip=54.240.27.18;
Date: Tue, 22 Nov 2022 01:06:25 +0000
Message-ID: <010101849cdf36fd-b21db532-45fc-4c27-a53d-9194640eb608-000000@us-west-2.amazonses.com>
To: bscattergood@roku.com, dmendenhall@roku.com, kcooper@roku.com,
        ksandvik@roku.com, mizhang@roku.com, najain@roku.com, pzhang@roku.com,
        sabellera@roku.com, snahibin@roku.com, tparker@roku.com
Cc: Andrey@localhost, Ryabinin@localhost, aryabinin@virtuozzo.com,
        Alexander@localhost, Potapenko@localhost, glider@google.com,
        Dmitry@localhost, Vyukov@localhost, dvyukov@google.com,
        kasan-dev@googlegroups.com
From: no-reply via kasan-dev <kasan-dev@googlegroups.com>
Reply-To: no-reply@roku.com ((Automation Account))
Subject: PERFORCE change 3224926: commit 663d8bcc524bf9dcae74e3c3eb7d30eb893145ef
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.22-54.240.27.18
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b=m7Nka8d6;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=BfX3WKZh;       spf=pass
 (google.com: domain of 010101849cdf36fd-b21db532-45fc-4c27-a53d-9194640eb608-000000@us-west-2.amazonses.com
 designates 54.240.27.18 as permitted sender) smtp.mailfrom=010101849cdf36fd-b21db532-45fc-4c27-a53d-9194640eb608-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
X-Original-From: no-reply@roku.com (Automation Account)
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

Change 3224926 by automation@source_control_dishonor on 2022/11/22 01:02:19

	commit 663d8bcc524bf9dcae74e3c3eb7d30eb893145ef
	Author: Linus Walleij <linus.walleij@linaro.org>
	Date:   Sun Oct 25 23:52:08 2020 +0100
	
	    ARM: 9014/2: Replace string mem* functions for KASan
	    
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
	    Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
	    Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
	    Reported-by: Russell King - ARM Linux <rmk+kernel@armlinux.org.uk>
	    Signed-off-by: Ahmad Fatoum <a.fatoum@pengutronix.de>
	    Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
	    Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
	    Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
	    Signed-off-by: Russell King <rmk+kernel@armlinux.org.uk>

Affected files ...

.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/boot/compressed/string.c#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/include/asm/string.h#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/kernel/armksyms.c#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/lib/memcpy.S#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/lib/memmove.S#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/lib/memset.S#2 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/boot/compressed/string.c#2 (text) ====

@@ -6,6 +6,25 @@
 
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

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/include/asm/string.h#2 (text) ====

@@ -4,6 +4,9 @@
 /*
  * We don't do inline string functions, since the
  * optimised inline asm versions are not small.
+ *
+ * The __underscore versions of some functions are for KASan to be able
+ * to replace them with instrumented versions.
  */
 
 #define __HAVE_ARCH_STRRCHR
@@ -14,15 +17,18 @@
 
 #define __HAVE_ARCH_MEMCPY
 extern void * memcpy(void *, const void *, __kernel_size_t) __nocapture(2);
+extern void *__memcpy(void *dest, const void *src, __kernel_size_t n);
 
 #define __HAVE_ARCH_MEMMOVE
 extern void * memmove(void *, const void *, __kernel_size_t) __nocapture(2);
+extern void *__memmove(void *dest, const void *src, __kernel_size_t n);
 
 #define __HAVE_ARCH_MEMCHR
 extern void * memchr(const void *, int, __kernel_size_t) __nocapture(-1);
 
 #define __HAVE_ARCH_MEMSET
 extern void * memset(void *, int, __kernel_size_t);
+extern void *__memset(void *s, int c, __kernel_size_t n);
 
 extern void __memzero(void *ptr, __kernel_size_t n);
 
@@ -38,4 +44,27 @@
 		(__p);							\
 	})
 
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
+#undef memcpy
+#undef memmove
+#undef memset
+#define memcpy(dst, src, len) __memcpy(dst, src, len)
+#define memmove(dst, src, len) __memmove(dst, src, len)
+#define memset(s, c, n) __memset(s, c, n)
+
+#ifndef __NO_FORTIFY
+#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
+#endif
+
+#endif
+
 #endif

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/kernel/armksyms.c#2 (text) ====

@@ -91,6 +91,11 @@
 EXPORT_SYMBOL(memmove);
 EXPORT_SYMBOL(memchr);
 EXPORT_SYMBOL(__memzero);
+#ifdef CONFIG_KASAN
+EXPORT_SYMBOL(__memset);
+EXPORT_SYMBOL(__memcpy);
+EXPORT_SYMBOL(__memmove);
+#endif
 
 EXPORT_SYMBOL(mmioset);
 EXPORT_SYMBOL(mmiocpy);

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/lib/memcpy.S#2 (text) ====

@@ -61,6 +61,8 @@
 
 /* Prototype: void *memcpy(void *dest, const void *src, size_t n); */
 
+.weak memcpy
+ENTRY(__memcpy)
 ENTRY(mmiocpy)
 ENTRY(memcpy)
 
@@ -68,3 +70,4 @@
 
 ENDPROC(memcpy)
 ENDPROC(mmiocpy)
+ENDPROC(__memcpy)

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/lib/memmove.S#2 (text) ====

@@ -27,12 +27,14 @@
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
@@ -225,3 +227,4 @@
 18:		backward_copy_shift	push=24	pull=8
 
 ENDPROC(memmove)
+ENDPROC(__memmove)

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/lib/memset.S#2 (text) ====

@@ -16,6 +16,8 @@
 	.text
 	.align	5
 
+.weak memset
+ENTRY(__memset)
 ENTRY(mmioset)
 ENTRY(memset)
 UNWIND( .fnstart         )
@@ -135,3 +137,4 @@
 UNWIND( .fnend   )
 ENDPROC(memset)
 ENDPROC(mmioset)
+ENDPROC(__memset)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010101849cdf36fd-b21db532-45fc-4c27-a53d-9194640eb608-000000%40us-west-2.amazonses.com.
