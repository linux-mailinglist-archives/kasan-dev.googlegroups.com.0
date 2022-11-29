Return-Path: <kasan-dev+bncBCJMBM5G5UCRB2O2SWOAMGQEAV3GYYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id D952963B7C8
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Nov 2022 03:24:42 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id r17-20020a056830135100b0066c3ca9c6d8sf5123617otq.15
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 18:24:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669688681; cv=pass;
        d=google.com; s=arc-20160816;
        b=WouHRH34/KBA9W58Ufv6T9y0OiWPehpYEgJYfvOyy00uwR2bk9wOBs9vMTdV1DuifK
         8OFvt6VkkvTZtz3PeF5fXnnLj9Rvbe1fNMlygLpLNYzT5MAtC9DdLfPL5jJ0gkenzM04
         Lgxz18Lfxon19OHFgc96jgDzxmm4Sv4gl+yz5tBYMfJuJxrBJM94qGSu4dBamvIakXO9
         zJYfbDljj12GxIjraOXEKxgqXxiTV3/LDpGHL/D54sSmVvhJpuW4W/pFE3BHaQs3+9YM
         9cw8pkASwx0sIMJSzCjpcNjYTGIL7R3rMfvkiHo+eCyjEPtCOeCBalVVO8k4wrpIb11b
         K1dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=H1/r4/dPfkupDzhir8hXNPwJpCQxb+UJK3V645l5JGE=;
        b=E0HBOm2tBCdx7LBp8zIIUeAiL8WYmjDtIavcr0TWHYAhYdZHqbiQSsCF1vbtkOMCdn
         CFiqB8ddk82ZPX9+0k5a5RVTzS33TtLaqNglqp0FqQHmsjpZYKo4GG8Q46o1sN16ufwc
         Iipw1jwW8UkxnWB5a2r10FD/A1yZbC9Z0/K0sV2flhoS77Wxu947q3l4zbJ435xYJP9a
         0zImBMSGP+J6LjdOV6Y2yqD3qhC+yFl/qlCTPMdbzOMn9xhqMIUpOtm9O24oqZ9bPSRt
         shdfpfZYHIiqFHhtlzwTGW22yvEOMPenQlxLv7uKXc0lhaDK7pDBxOWJehhuv36lgfVx
         Yv5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=G2Jg8fvi;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=LnjE2bvO;
       spf=pass (google.com: domain of 01010184c1335c71-3959e4d9-f958-46ef-bbbc-090aecdf0174-000000@us-west-2.amazonses.com designates 54.240.27.185 as permitted sender) smtp.mailfrom=01010184c1335c71-3959e4d9-f958-46ef-bbbc-090aecdf0174-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=H1/r4/dPfkupDzhir8hXNPwJpCQxb+UJK3V645l5JGE=;
        b=tjsAe1dAHEavqc7/RtZnlWb90mcDWLoeYVh9dkPT4ORoi42IEh8I6ASNUjsCoo4iQk
         U8rWHmD1n//COtZi6VOt7mZvxHD4+AkLa0zTyRNB1rJm3n/Xxm0G0vgTbSQFr8cxyObv
         i+8xoyX5alUqTu8U+PImD4ZpEDFTM5WVzscxVvA5o5+HEg2J4i72RItZvgUZSd9wT80P
         WiI/5oXC3pK1FXdMMys2NKgkckW5vGz3f2Ex1SdAONLht80vMDKK5jdDaCqNlT4L6YdR
         NFhsJ1zG16K4EjMWjtKe6/49SIU8Ry//MMTsRUG01KfOQptfw81gMMJo6W9X4QlPmp6T
         Sq7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=H1/r4/dPfkupDzhir8hXNPwJpCQxb+UJK3V645l5JGE=;
        b=P+fBQE9TIpCMEwAeqy081XBEMqJV8eGdVrzDajmpeXB4VuzZbTdqmZiQC6qPplJ91G
         eCalymgMKWQMre7OJRW6+xU/VPUGCqOYTA6teh8HMPfYfzJYgyzvJWeFR+yY8j50SQFK
         zyuaPGD7LvujxHtSWOocNN9dcGxOoF/alGlOVBjvU6VnvGlFDqWrFRaEV2vG5JPlCKU/
         dia1U66xEb7EY2eLUwURkZVePDC5JEGr8luvL6Fl3OPeLmdbxnAKHeSU8mhKgTjkj/GU
         HIpRdcR1gOV2rg4crRKADKdxaO/ZGv+mrNFRcDROIqPy3UC07RUs9VVqHzjnOCeu5QSm
         opqw==
X-Gm-Message-State: ANoB5pntdk2Wy8wlnzvuypIGr+Ghj+H8TmDKa/Fxea6n6EVngaer6TcK
	aHTD7WeEt6wWZjrW6BCEp6Y=
X-Google-Smtp-Source: AA0mqf5r1kzCnpkS8bLWTUtBvrp6nfe6oRvE3mWLlx3NeIKeO5XxBH1u7v3Dt3H8gq2WWTLuLrIi+Q==
X-Received: by 2002:aca:6545:0:b0:35a:249f:aa0c with SMTP id j5-20020aca6545000000b0035a249faa0cmr16589038oiw.222.1669688681318;
        Mon, 28 Nov 2022 18:24:41 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:de88:0:b0:345:9a88:c799 with SMTP id v130-20020acade88000000b003459a88c799ls3788859oig.5.-pod-prod-gmail;
 Mon, 28 Nov 2022 18:24:40 -0800 (PST)
X-Received: by 2002:a05:6808:14d4:b0:35a:a4f:a95d with SMTP id f20-20020a05680814d400b0035a0a4fa95dmr15936877oiw.86.1669688680844;
        Mon, 28 Nov 2022 18:24:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669688680; cv=none;
        d=google.com; s=arc-20160816;
        b=aDxHEsZmSS4oRo/Up+cGJnAv4c6kb3VBPzdIooziMqR5+Hfevl2Npov1R797NOk/Il
         WuX69NibpAh6mMZOAIysd5swvXD/9lz497jOaSraKPldJyUoQNsQyH4nGUiAYe39Gaoy
         hEXPYbkkdPSpPW9/TaAJw7eMW97xx+sT+36O7K5tPHpArr6mymZh5JgvolQ9KJhirSoL
         hPsSEN9th4jSOPdt7IRRN+ovh24qlZNZp4aqXVmdHWhblFsdgC1zYLqwMsw4wFrdj74L
         CUzWYBrXXNXTSpwmxbLwDJfFedU3Sy+Gm5gAq237BPmUDVary4K0P07+FbYLf+BKOvBO
         x71Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=I35Al2HIR/ATo8EJ18eHL76f3YK+oee0iJ8WIJMBaXg=;
        b=tUOcPnbj+cHEAKsggQUSDAPH7Anf8dAFMkTUJJtQNg/6Ke8WxE7T6dX1E6bexslohf
         uhlJ1hOvegFSCuJVlH7IYxFjDCmHYdbyLKaF4q8/MYFTug0MlUXzAxMze6iN3TwDBF1A
         v+eOYcrCslwCsciCoRAueJqQEU0HsztaYz1n3F/1ntvmMsQq0EY4C+ab9fT7X3mb8B9q
         bvrT0jKGV4qbqcpb7eU9B6HcLj34aTGn2fpeFdpqutXeZMfp2WNgS5fI05WrlEkz7hpv
         3dV086YJctaT3PwfjyHIF41OWBegC7T7KhdhYwBErkNUVAkeNhiLEP1o0EgOvA6jG1Al
         f7Zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=G2Jg8fvi;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=LnjE2bvO;
       spf=pass (google.com: domain of 01010184c1335c71-3959e4d9-f958-46ef-bbbc-090aecdf0174-000000@us-west-2.amazonses.com designates 54.240.27.185 as permitted sender) smtp.mailfrom=01010184c1335c71-3959e4d9-f958-46ef-bbbc-090aecdf0174-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-185.smtp-out.us-west-2.amazonses.com (a27-185.smtp-out.us-west-2.amazonses.com. [54.240.27.185])
        by gmr-mx.google.com with ESMTPS id y19-20020a056871011300b00143cfb377b2si263683oab.2.2022.11.28.18.24.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 28 Nov 2022 18:24:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 01010184c1335c71-3959e4d9-f958-46ef-bbbc-090aecdf0174-000000@us-west-2.amazonses.com designates 54.240.27.185 as permitted sender) client-ip=54.240.27.185;
Date: Tue, 29 Nov 2022 02:24:39 +0000
Message-ID: <01010184c1335c71-3959e4d9-f958-46ef-bbbc-090aecdf0174-000000@us-west-2.amazonses.com>
To: bscattergood@roku.com, dmendenhall@roku.com, kcooper@roku.com,
        ksandvik@roku.com, mizhang@roku.com, najain@roku.com, pzhang@roku.com,
        sabellera@roku.com, snahibin@roku.com, tparker@roku.com
Cc: Andrey@localhost, Ryabinin@localhost, aryabinin@virtuozzo.com,
        Alexander@localhost, Potapenko@localhost, glider@google.com,
        Dmitry@localhost, Vyukov@localhost, dvyukov@google.com,
        kasan-dev@googlegroups.com
From: no-reply via kasan-dev <kasan-dev@googlegroups.com>
Reply-To: no-reply@roku.com ((Automation Account))
Subject: PERFORCE change 3225581: commit 587b66404ca38da50b47fe75efcf8f27df27c58f
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.29-54.240.27.185
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b=G2Jg8fvi;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=LnjE2bvO;       spf=pass
 (google.com: domain of 01010184c1335c71-3959e4d9-f958-46ef-bbbc-090aecdf0174-000000@us-west-2.amazonses.com
 designates 54.240.27.185 as permitted sender) smtp.mailfrom=01010184c1335c71-3959e4d9-f958-46ef-bbbc-090aecdf0174-000000@us-west-2.amazonses.com;
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

Change 3225581 by automation@source_control_dishonor on 2022/11/29 02:20:10

	commit 587b66404ca38da50b47fe75efcf8f27df27c58f
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

.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/boot/compressed/string.c#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/include/asm/string.h#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/kernel/armksyms.c#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/lib/memcpy.S#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/lib/memmove.S#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/lib/memset.S#2 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/boot/compressed/string.c#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/include/asm/string.h#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/kernel/armksyms.c#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/lib/memcpy.S#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/lib/memmove.S#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/lib/memset.S#2 (text) ====

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01010184c1335c71-3959e4d9-f958-46ef-bbbc-090aecdf0174-000000%40us-west-2.amazonses.com.
