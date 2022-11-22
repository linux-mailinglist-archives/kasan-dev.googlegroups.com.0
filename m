Return-Path: <kasan-dev+bncBCJMBM5G5UCRB6NV6CNQMGQENPZXHEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id D64E263317B
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 01:42:34 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id u3-20020a056a00124300b0056d4ab0c7cbsf8309833pfi.7
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 16:42:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669077753; cv=pass;
        d=google.com; s=arc-20160816;
        b=N0A3XVU/n6KOzhn+U7y7fKMq2v6Kih+D0cIe/2mNXyfePLuY4xZiFBiOfEyrY8moTC
         NtsE8op/yYp58k5XZgmmHNWvn2B76kVZh53U85aMLjNd3HzVjEEN+DJZ2kZ7lIeMdr1S
         YxkrFn66ER6q/ZCbM4La8hYobsiGaUzHfmGyAAjqyfsffMayneHKSXmc17v0VYVi9SOQ
         rgUwA9T3TyRsxTmFWvrlHzoD3h02gxL+baO/e3JI04Rg23z03myutff43M/IphpiafCr
         lDCODKKhaFbyJ6kl9CLXu9zXG8L0+BlFibaN6iMJOHleIpqLF4YOcywVwngO6/JocjLm
         ysdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=HWJTOymM7p/P+dNBZV3sGyKlxipWqHqlDIzmFVNwv1U=;
        b=DlF8LeNP/aNKJv1t1/fc235I8x/LzPzAlbpSq9m7nahx38iCkzxuRE3rUCEovwvqO4
         r//A8BdsSSsskPr3mI7OZr06Lu8HJCFpk6af4ZFvbADnSqRqWrg4Zincc8GtRJETP+US
         m3O+kg6saSel96mLBKuM5aqcsQOrA0g4FV/TBdefPFA7qTUI7mMd0Dxgz0VlPUZPmiNL
         HTTZzTlYzDM32xXUrt4FZIp0ZUCkVNOeT0rsN2UBcgCmIGfHEah1/n/nKKbYhvHQGedB
         IgY+1oQwwRz4fLkp/xytqRLMGuX/0YlgkaZ3av8TGrV7lYjB/I/S+1nyvphd+HVgshJK
         mlsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=Z7M+xb65;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=Trl2QSMF;
       spf=pass (google.com: domain of 010101849cc958c9-7351f01b-9006-40e1-a191-92312c91d3ca-000000@us-west-2.amazonses.com designates 54.240.27.188 as permitted sender) smtp.mailfrom=010101849cc958c9-7351f01b-9006-40e1-a191-92312c91d3ca-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HWJTOymM7p/P+dNBZV3sGyKlxipWqHqlDIzmFVNwv1U=;
        b=HrSVgRvUvSZ7sD8cV31T/7i/P8oF8GZWTe9v0u5UsspH9T5/hmdhdtoZ/9OEBZbpgn
         SiG5WyjuiGfkJTZ70f2POb3l4nSMpvd8x9FaV0QKszGtWSErZoYfb1woedi+q1qA5re3
         k74hMJgSunXTd17YL8JwEoj/fF4ZYNBJLx079sh7psTsEtvCxHpu4AtjAUL2A10U3VM7
         8TXD/Wo+b8MkN4B1z8mNQBoYbunhhgmCTJkXTR0pypdQUe3awmFyt0KQk5vyx8WvFnQo
         OzWswbEG4YWT672FHdZy4cBlEKHXN/sLh8SQtNo0Byym3arAcGfu4X9ddROGHFGxHvjj
         DC5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=HWJTOymM7p/P+dNBZV3sGyKlxipWqHqlDIzmFVNwv1U=;
        b=Z7iqfH5/xP21gXOtwKIDWu2FR197LSfGHMDj9QJeru2A36She1uNAwibbqk1maXziB
         /kzT8e/e+jg5oXMKFRKNRxfGEO22qEfzbvVZVw1zEUpHXPmpPD5jUuF7sM9FBrF8hMve
         3dpXZl/V5a94rqTlbPz3soe0t1wP/VTEAF81mmrBhOYKMMO9zBwtj+VFIqN3tA4OP+1Z
         DLVJXmZj0n3I8TBq2zRSKvimketJOlH5P7MfIVBdlN6TvsTA+tJt2y/oiHhSQ+ILeVLP
         R+J5A+zK9WfxIBdZddg57Zf9Iu24WxaqHLzKpJ63bFW8T3sVoTiYh9W36uBI6byJbSqi
         Jk5w==
X-Gm-Message-State: ANoB5pkWm+e1gV/tBt0yxXaOsBLwfacPCaOCE7vu+5WIqibwiisZedye
	XTQeYGnWoMWONvTYakgL+Ug=
X-Google-Smtp-Source: AA0mqf7UhM4rYpI/VOmdKN7DC7oThgsWCGJTTS9oyE2dopDUAKqO1F4X+0lpf+7vPnzIBL+BhWNPjA==
X-Received: by 2002:a17:902:da83:b0:189:2809:2f11 with SMTP id j3-20020a170902da8300b0018928092f11mr4896020plx.105.1669077753400;
        Mon, 21 Nov 2022 16:42:33 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1c06:0:b0:561:e77b:c7c2 with SMTP id c6-20020a621c06000000b00561e77bc7c2ls6614759pfc.4.-pod-prod-gmail;
 Mon, 21 Nov 2022 16:42:32 -0800 (PST)
X-Received: by 2002:a05:6a02:118:b0:477:8106:b518 with SMTP id bg24-20020a056a02011800b004778106b518mr5053500pgb.106.1669077752639;
        Mon, 21 Nov 2022 16:42:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669077752; cv=none;
        d=google.com; s=arc-20160816;
        b=Wl47XwN8Hg9XsEBoD3ml+5cibmwYViQJmNSsmLgZiWckCm2JliMd5QYJyIVUuxRiSV
         NYSVzWHcOIhmPXrreFoe8t66ITUxapCtl+VN0P0I3k6vJ+A/3S/D4Bys4WWJbDVWJqGy
         VUX++gaGhCGV4bWyehJLfZpXTVrRlciUU2vJW4ajOY1D4y+zCnum9TjsqwAgDI/DB5Ct
         TYPBoFHOhkXVqEfafdkOOTJtvSfL6C8luXPY7YJYkJ5ogvTK8CasymRYPjYpG/EqEKY8
         8Oq5YFUFxW/E5Qa8c7YCvdq1+MeSH9nZonyU7zoIcM5rbmiEt3+c1ebQR6CvTBCFq35Z
         /58Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=IQWkibo4TevFr3edl3eY0p0x87hh2w3vTSkW4bSCklg=;
        b=qKlLyW2RN0RirPbcuTSYGwntdIWgmHBIeEMahmAq+yvf9/NBh7rmDITvXUjcp/Ft+v
         ykCtpmhh0kZ8EwCIspZUfc4Px9+VhWrSmVxczqQaTrX6qSigaxaRQ8mSSH7XdP3GOEK/
         zhb48/meSOHlRJ3xi8nDhk3+b/dWMpzU7qp5uyjhH2G+2Ul9WDo8lL2xioYgQv5noDZF
         XF4nOiLSeS8ggKMQP52c+1Or5qr4nnLRzqeO3XcRfDnA0RI+3i4Vn1HEHN3CpuxZLiH3
         2QeBCpad8xDZYOOZGfPXbseJpF8C1kwK3Qw81uNuJGja5nuPdmBzUu5mDsjgP+y0ZXpf
         ogpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=Z7M+xb65;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=Trl2QSMF;
       spf=pass (google.com: domain of 010101849cc958c9-7351f01b-9006-40e1-a191-92312c91d3ca-000000@us-west-2.amazonses.com designates 54.240.27.188 as permitted sender) smtp.mailfrom=010101849cc958c9-7351f01b-9006-40e1-a191-92312c91d3ca-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-188.smtp-out.us-west-2.amazonses.com (a27-188.smtp-out.us-west-2.amazonses.com. [54.240.27.188])
        by gmr-mx.google.com with ESMTPS id bu3-20020a632943000000b004772bae20ebsi482184pgb.5.2022.11.21.16.42.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 16:42:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 010101849cc958c9-7351f01b-9006-40e1-a191-92312c91d3ca-000000@us-west-2.amazonses.com designates 54.240.27.188 as permitted sender) client-ip=54.240.27.188;
Date: Tue, 22 Nov 2022 00:42:32 +0000
Message-ID: <010101849cc958c9-7351f01b-9006-40e1-a191-92312c91d3ca-000000@us-west-2.amazonses.com>
To: bscattergood@roku.com, dmendenhall@roku.com, kcooper@roku.com,
        ksandvik@roku.com, mizhang@roku.com, najain@roku.com, pzhang@roku.com,
        sabellera@roku.com, snahibin@roku.com, tparker@roku.com
Cc: Andrey@localhost, Ryabinin@localhost, aryabinin@virtuozzo.com,
        Alexander@localhost, Potapenko@localhost, glider@google.com,
        Dmitry@localhost, Vyukov@localhost, dvyukov@google.com,
        kasan-dev@googlegroups.com
From: no-reply via kasan-dev <kasan-dev@googlegroups.com>
Reply-To: no-reply@roku.com ((Automation Account))
Subject: PERFORCE change 3224910: commit fb14721d661e08479bb920ca883be3142b69015e
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.22-54.240.27.188
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b=Z7M+xb65;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=Trl2QSMF;       spf=pass
 (google.com: domain of 010101849cc958c9-7351f01b-9006-40e1-a191-92312c91d3ca-000000@us-west-2.amazonses.com
 designates 54.240.27.188 as permitted sender) smtp.mailfrom=010101849cc958c9-7351f01b-9006-40e1-a191-92312c91d3ca-000000@us-west-2.amazonses.com;
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

Change 3224910 by automation@vsergiienko-flipday-internal-rtd1395-nemo on 2022/11/22 00:39:55

	commit fb14721d661e08479bb920ca883be3142b69015e
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

.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/boot/compressed/string.c#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/include/asm/string.h#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/kernel/armksyms.c#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/lib/memcpy.S#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/lib/memmove.S#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/lib/memset.S#2 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/boot/compressed/string.c#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/include/asm/string.h#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/kernel/armksyms.c#2 (text) ====

@@ -92,6 +92,12 @@
 EXPORT_SYMBOL(memchr);
 EXPORT_SYMBOL(__memzero);
 
+#ifdef CONFIG_KASAN
+EXPORT_SYMBOL(__memset);
+EXPORT_SYMBOL(__memcpy);
+EXPORT_SYMBOL(__memmove);
+#endif
+
 EXPORT_SYMBOL(mmioset);
 EXPORT_SYMBOL(mmiocpy);
 

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/lib/memcpy.S#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/lib/memmove.S#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/lib/memset.S#2 (text) ====

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010101849cc958c9-7351f01b-9006-40e1-a191-92312c91d3ca-000000%40us-west-2.amazonses.com.
