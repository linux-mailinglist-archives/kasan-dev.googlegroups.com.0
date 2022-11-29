Return-Path: <kasan-dev+bncBCJMBM5G5UCRBBG4SWOAMGQEYTIX74I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B18663B7CC
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Nov 2022 03:27:18 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id f4-20020a17090a700400b0021925293dcfsf4440892pjk.8
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 18:27:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669688836; cv=pass;
        d=google.com; s=arc-20160816;
        b=uT6HpEOF1jyUleabk+ZHBGcS8sYisfs58DpAmwu7SKZ8TgcFlofXpeAh/v8l49Eb29
         F6231BaqwaUViv7kaIp3uPp+FsqOCjGkCfjJ5fhlUiEcyfjhpc+XrfcEDCT6uCXUneEn
         xltIs4YaHSU0KXdv492RKAQYA6QPdAET5J4zc+Bb46A4/UWWIS/kCklf9NuErsdndxN1
         QUT3dyoKuY4ZMfCnqgG94S/xOQz5dGxDJXr8s5bJ82MWA1d4Y1tkszFgf7k4ohV5prgp
         I3VIhwu+w5LyBo1XRsW2lHYluVzBgccuSeIOV7N4oTlYvCTHaiODaMOxiII//GCL6Yl/
         SrOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=vYN5k7r4IcMk5kyZcP+Qev5g/4EdpDzAMNaF3g+q+w0=;
        b=Rd3amqRgz9it13BNZ4eTltXew14hxU85GETRwjAc/EzftPFw6zKl6+yZSgPIEaEslq
         TwYd8ZLzdTGAnVAyJSlCavvcViAYeA2D7fIj2mxcToff468CcUyuav2fYNwKqxxKJIwi
         fe+ZvIDp0M6iHePf25bFynxzNGLIiFTa4/n1JG1G23v7IavY0ZvNJ4pFwTcYO3FpnH7L
         QEdwpzA/7is4PMrUDLPJW9/DG0LKd2rRdkX+GYX+J10lloos3JiMfTYUlBVpGUzUtgdk
         IxQ6yj9jFQ60h7ZP3NYku5Yhx6TkHwYFMeE6zTw5ghRtargt56JWDt09jytzcyi9gKQx
         KtKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=NdJCGoG1;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=bapPYSlM;
       spf=pass (google.com: domain of 01010184c135bb14-cabbfbc6-f261-41c9-ace5-3cd9e4c1472d-000000@us-west-2.amazonses.com designates 54.240.27.56 as permitted sender) smtp.mailfrom=01010184c135bb14-cabbfbc6-f261-41c9-ace5-3cd9e4c1472d-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vYN5k7r4IcMk5kyZcP+Qev5g/4EdpDzAMNaF3g+q+w0=;
        b=NsmLIi+J4DR3X8LsHFfz9tkzm0JvNpdtnfA7EqvV86t9OxYNenfqS4pDxvily/fYZS
         wwFognoDa9TyWkrd+bCnv59Tdd+bbGjfrHlFl4D7fnl+niXP7VFbyBVRcM1hPOU6vf2c
         eck6+ypnkCEN7mluFUNeOnEveceP33bi1oSDcCjkyq4mZlnsNk1K6MSea7bvNvpg8X31
         41Nqlgg0FwvVKSTwCkYzaCKhKeNCQPu2FF8GdgOfVLzrllRPv2f40xZQ926EThLwV3iO
         BxUtQzC/e60Q/PDe+NumKi2kStlijenwMA1vqE9upsHTYK9XDo0wH9uXAO4dgk2ftkCC
         q7Cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=vYN5k7r4IcMk5kyZcP+Qev5g/4EdpDzAMNaF3g+q+w0=;
        b=7+OqVoLM53EqcwOFtmsVBOhY3P3eXBmzvupTvLUR4efIvKOrgZeXJ8ez1dCDTz+eWc
         XnJodZ4fhfHPtqPEA4bj9CE8xhHYMmi58E65n2sHSUAfRP+pxekcFbnmzTvv/VxRsZFy
         IGw6YCZ6bT542T4ZBA9mdxw75KtHXiTs1dCy3uXszFl70UjMX30EGsnI5tNU+6V36P8R
         SOoj/qsYl7DvJz9bAxZ/CTlZyOxTuUnCalO13/MUg4DWkBxIBFtCJOO2sV4rR0LmNB6U
         suNqcrERXreAN7/yTKBFNzEJmB50800p8URFAQdMoWGGjztkBIZJXIeN+IzbtK1gYcKc
         Pa6Q==
X-Gm-Message-State: ANoB5pnT7SJgmpPcEuOWTmcFSvjENqS+shErcCrSZDOl65BJwoXwkywG
	oj07ehKUQKTP/kHKqunRoyg=
X-Google-Smtp-Source: AA0mqf4Cgo4448zHEjlRpmK0QRK6iPaMWk4qp3t9OEW5D+zf1+UijNCNKmiDGTgZMd2MiApLe2BDaQ==
X-Received: by 2002:a17:902:a5ca:b0:186:bb48:2b34 with SMTP id t10-20020a170902a5ca00b00186bb482b34mr35793293plq.1.1669688836156;
        Mon, 28 Nov 2022 18:27:16 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7181:b0:219:4318:f24e with SMTP id
 i1-20020a17090a718100b002194318f24els2218846pjk.0.-pod-control-gmail; Mon, 28
 Nov 2022 18:27:15 -0800 (PST)
X-Received: by 2002:a17:90a:94c3:b0:219:e20:9bf7 with SMTP id j3-20020a17090a94c300b002190e209bf7mr19161406pjw.61.1669688835407;
        Mon, 28 Nov 2022 18:27:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669688835; cv=none;
        d=google.com; s=arc-20160816;
        b=UJLHEyrpAzdKSWH12fdtBSzCUQ0D4828P9M6WjqtLSwhFmtAIAQlmznlKFJxCw7GQF
         N35yBAI+878cOE02I1S2WVmTMQB8ZbF38gD577B8Vmv3j8H5+/879nXKlds6F+GeHkRQ
         QaB1ljLWYVKam8ca7uE/uCYhDMmZzRaFMJGNmTWmiJ4ygUSb594KbYZX2DWAsgDuOUeo
         fY5wl4yL5u/xWJ3UtEC+0nJHKaHKElwarM/H+b3wFOAeJOKcJ3PhqJbtJROYUdvBTlbt
         vNJGD69LSeaNX77nDuaflpDfgb3bTY3PtPmFIhM+kAukjvb9SrO5hXVWBIXBZm+5CvlD
         TuUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=TSVkL2mu2rCqOv8hJfy6jmcT0wdoktd3ZvVvQ1FCI7w=;
        b=YU8dM8OwT8izxIeLN4qkIRjltdpbPlR7S3+j3W1pjZLUKgVAy57p6hUDJriMfEijEM
         uCLa1OUpgsh3sS9/Rf8MnpGj6Xxno+Tvi2Lp3zEl/XsSRaXRz18gTNVhCcihwVUikYj4
         8ej4hXxCH3qmb2jD2e/PmVwsOKAvMiGC/GcWtkH8TSQMmJzuR53qQmxlw5fjdAepIoFC
         VKv2V4kIWFBb8niPJdT2xQN+uoiyFpmv0ZrJtGGyLL9ku3LVnZc4GDhc+47rk6+epek+
         8xR9x8xS6DUkLt6TWrze+fDbmwkk0DomJTuPF91eAwSADYqs/sfBiQ0MyYcwc1VRgt37
         40Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=NdJCGoG1;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=bapPYSlM;
       spf=pass (google.com: domain of 01010184c135bb14-cabbfbc6-f261-41c9-ace5-3cd9e4c1472d-000000@us-west-2.amazonses.com designates 54.240.27.56 as permitted sender) smtp.mailfrom=01010184c135bb14-cabbfbc6-f261-41c9-ace5-3cd9e4c1472d-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-56.smtp-out.us-west-2.amazonses.com (a27-56.smtp-out.us-west-2.amazonses.com. [54.240.27.56])
        by gmr-mx.google.com with ESMTPS id iw14-20020a170903044e00b00189348ab16fsi833692plb.13.2022.11.28.18.27.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 28 Nov 2022 18:27:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 01010184c135bb14-cabbfbc6-f261-41c9-ace5-3cd9e4c1472d-000000@us-west-2.amazonses.com designates 54.240.27.56 as permitted sender) client-ip=54.240.27.56;
Date: Tue, 29 Nov 2022 02:27:14 +0000
Message-ID: <01010184c135bb14-cabbfbc6-f261-41c9-ace5-3cd9e4c1472d-000000@us-west-2.amazonses.com>
To: bscattergood@roku.com, dmendenhall@roku.com, kcooper@roku.com,
        ksandvik@roku.com, mizhang@roku.com, najain@roku.com, pzhang@roku.com,
        sabellera@roku.com, snahibin@roku.com, tparker@roku.com
Cc: Alexander@localhost, Potapenko@localhost, glider@google.com,
        Dmitry@localhost, Vyukov@localhost, dvyukov@google.com,
        kasan-dev@googlegroups.com, Mike@localhost, Rapoport@localhost,
        rppt@linux.ibm.com
From: no-reply via kasan-dev <kasan-dev@googlegroups.com>
Reply-To: no-reply@roku.com ((Automation Account))
Subject: PERFORCE change 3225583: commit 1ab472c27864adb2d693f28a655f169b8c12a646
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.29-54.240.27.56
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b=NdJCGoG1;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=bapPYSlM;       spf=pass
 (google.com: domain of 01010184c135bb14-cabbfbc6-f261-41c9-ace5-3cd9e4c1472d-000000@us-west-2.amazonses.com
 designates 54.240.27.56 as permitted sender) smtp.mailfrom=01010184c135bb14-cabbfbc6-f261-41c9-ace5-3cd9e4c1472d-000000@us-west-2.amazonses.com;
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

Change 3225583 by automation@source_control_dishonor on 2022/11/29 02:20:43

	commit 1ab472c27864adb2d693f28a655f169b8c12a646
	Author: Linus Walleij <linus.walleij@linaro.org>
	Date:   Sun Oct 25 23:55:16 2020 +0100
	
	    ARM: 9016/2: Initialize the mapping of KASan shadow memory
	    
	    This patch initializes KASan shadow region's page table and memory.
	    There are two stage for KASan initializing:
	    
	    1. At early boot stage the whole shadow region is mapped to just
	       one physical page (kasan_zero_page). It is finished by the function
	       kasan_early_init which is called by __mmap_switched(arch/arm/kernel/
	       head-common.S)
	    
	    2. After the calling of paging_init, we use kasan_zero_page as zero
	       shadow for some memory that KASan does not need to track, and we
	       allocate a new shadow space for the other memory that KASan need to
	       track. These issues are finished by the function kasan_init which is
	       call by setup_arch.
	    
	    When using KASan we also need to increase the THREAD_SIZE_ORDER
	    from 1 to 2 as the extra calls for shadow memory uses quite a bit
	    of stack.
	    
	    As we need to make a temporary copy of the PGD when setting up
	    shadow memory we create a helpful PGD_SIZE definition for both
	    LPAE and non-LPAE setups.
	    
	    The KASan core code unconditionally calls pud_populate() so this
	    needs to be changed from BUG() to do {} while (0) when building
	    with KASan enabled.
	    
	    After the initial development by Andre Ryabinin several modifications
	    have been made to this code:
	    
	    Abbott Liu <liuwenliang@huawei.com>
	    - Add support ARM LPAE: If LPAE is enabled, KASan shadow region's
	      mapping table need be copied in the pgd_alloc() function.
	    - Change kasan_pte_populate,kasan_pmd_populate,kasan_pud_populate,
	      kasan_pgd_populate from .meminit.text section to .init.text section.
	      Reported by Florian Fainelli <f.fainelli@gmail.com>
	    
	    Linus Walleij <linus.walleij@linaro.org>:
	    - Drop the custom mainpulation of TTBR0 and just use
	      cpu_switch_mm() to switch the pgd table.
	    - Adopt to handle 4th level page tabel folding.
	    - Rewrite the entire page directory and page entry initialization
	      sequence to be recursive based on ARM64:s kasan_init.c.
	    
	    Ard Biesheuvel <ardb@kernel.org>:
	    - Necessary underlying fixes.
	    - Crucial bug fixes to the memory set-up code.
	    
	    Co-developed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
	    Co-developed-by: Abbott Liu <liuwenliang@huawei.com>
	    Co-developed-by: Ard Biesheuvel <ardb@kernel.org>
	    
	    Cc: Alexander Potapenko <glider@google.com>
	    Cc: Dmitry Vyukov <dvyukov@google.com>
	    Cc: kasan-dev@googlegroups.com
	    Cc: Mike Rapoport <rppt@linux.ibm.com>
	    Acked-by: Mike Rapoport <rppt@linux.ibm.com>
	    Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
	    Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
	    Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
	    Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
	    Reported-by: Russell King - ARM Linux <rmk+kernel@armlinux.org.uk>
	    Reported-by: Florian Fainelli <f.fainelli@gmail.com>
	    Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
	    Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
	    Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
	    Signed-off-by: Ard Biesheuvel <ardb@kernel.org>
	    Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
	    Signed-off-by: Russell King <rmk+kernel@armlinux.org.uk>

Affected files ...

.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/include/asm/kasan.h#1 add
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/include/asm/pgalloc.h#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/include/asm/thread_info.h#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/kernel/head-common.S#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/kernel/setup.c#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/mm/Makefile#3 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/mm/kasan_init.c#1 add
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/mm/pgd.c#2 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/include/asm/pgalloc.h#2 (text) ====

@@ -27,6 +27,7 @@
 #define _PAGE_KERNEL_TABLE	(PMD_TYPE_TABLE | PMD_BIT4 | PMD_DOMAIN(DOMAIN_KERNEL))
 
 #ifdef CONFIG_ARM_LPAE
+#define PGD_SIZE		(PTRS_PER_PGD * sizeof(pgd_t))
 
 static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
 {
@@ -50,13 +51,19 @@
 }
 
 #else	/* !CONFIG_ARM_LPAE */
+#define PGD_SIZE		(PAGE_SIZE << 2)
 
 /*
  * Since we have only two-level page tables, these are trivial
  */
 #define pmd_alloc_one(mm,addr)		({ BUG(); ((pmd_t *)2); })
 #define pmd_free(mm, pmd)		do { } while (0)
+#ifdef CONFIG_KASAN
+/* The KASan core unconditionally calls pud_populate() on all architectures */
+#define pud_populate(mm,pmd,pte)	do { } while (0)
+#else
 #define pud_populate(mm,pmd,pte)	BUG()
+#endif
 #define pud_populate_kernel(mm,pmd,pte)	BUG()
 
 #endif	/* CONFIG_ARM_LPAE */

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/include/asm/thread_info.h#2 (text) ====

@@ -16,7 +16,15 @@
 #include <asm/fpstate.h>
 #include <asm/page.h>
 
+#ifdef CONFIG_KASAN
+/*
+ * KASan uses a lot of extra stack space so the thread size order needs to
+ * be increased.
+ */
+#define THREAD_SIZE_ORDER	2
+#else
 #define THREAD_SIZE_ORDER	1
+#endif
 #define THREAD_SIZE		(PAGE_SIZE << THREAD_SIZE_ORDER)
 #define THREAD_START_SP		(THREAD_SIZE - 8)
 

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/kernel/head-common.S#2 (text) ====

@@ -101,6 +101,9 @@
 	str	r2, [r6]			@ Save atags pointer
 	cmp	r7, #0
 	strne	r0, [r7]			@ Save control register values
+#ifdef CONFIG_KASAN
+	bl	kasan_early_init
+#endif
 	b	start_kernel
 ENDPROC(__mmap_switched)
 

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/kernel/setup.c#2 (text) ====

@@ -62,6 +62,7 @@
 #include <asm/unwind.h>
 #include <asm/memblock.h>
 #include <asm/virt.h>
+#include <asm/kasan.h>
 
 #include "atags.h"
 
@@ -1121,6 +1122,7 @@
 	early_ioremap_reset();
 
 	paging_init(mdesc);
+	kasan_init();
 	request_standard_resources(mdesc);
 
 	if (mdesc->restart)

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/mm/Makefile#3 (text) ====

@@ -1,6 +1,7 @@
 #
 # Makefile for the linux arm-specific parts of the memory manager.
 #
+ccflags-y += -I$(srctree)/mm/kasan/
 
 obj-y				:= dma-mapping.o extable.o fault.o init.o \
 				   iomap.o
@@ -108,3 +109,6 @@
 obj-$(CONFIG_CACHE_XSC3L2)	+= cache-xsc3l2.o
 obj-$(CONFIG_CACHE_TAUROS2)	+= cache-tauros2.o
 obj-$(CONFIG_CACHE_UNIPHIER)	+= cache-uniphier.o
+
+KASAN_SANITIZE_kasan_init.o	:= n
+obj-$(CONFIG_KASAN)		+= kasan_init.o

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/mm/pgd.c#2 (text) ====

@@ -64,7 +64,21 @@
 	new_pmd = pmd_alloc(mm, new_pud, 0);
 	if (!new_pmd)
 		goto no_pmd;
-#endif
+#ifdef CONFIG_KASAN
+	/*
+	 * Copy PMD table for KASAN shadow mappings.
+	 */
+	init_pgd = pgd_offset_k(TASK_SIZE);
+	init_p4d = p4d_offset(init_pgd, TASK_SIZE);
+	init_pud = pud_offset(init_p4d, TASK_SIZE);
+	init_pmd = pmd_offset(init_pud, TASK_SIZE);
+	new_pmd = pmd_offset(new_pud, TASK_SIZE);
+	memcpy(new_pmd, init_pmd,
+	       (pmd_index(MODULES_VADDR) - pmd_index(TASK_SIZE))
+	       * sizeof(pmd_t));
+	clean_dcache_area(new_pmd, PTRS_PER_PMD * sizeof(pmd_t));
+#endif /* CONFIG_KASAN */
+#endif /* CONFIG_LPAE */
 
 	if (!vectors_high()) {
 		/*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01010184c135bb14-cabbfbc6-f261-41c9-ace5-3cd9e4c1472d-000000%40us-west-2.amazonses.com.
