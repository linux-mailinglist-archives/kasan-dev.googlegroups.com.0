Return-Path: <kasan-dev+bncBCJMBM5G5UCRBLWC6CNQMGQE2YS4PVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id AAFF56331E8
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 02:09:03 +0100 (CET)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-393fc59d09fsf105708277b3.18
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 17:09:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669079342; cv=pass;
        d=google.com; s=arc-20160816;
        b=T7Mnj9Ido39HWJ9sIUDFxdT1TEegU5kO9k0IEf3BYZK3NcH3vPimhEcP+jFz46aGPW
         y4/Zv85GL1VvoVGhltW9plrU4hBAgZDK8XE55NTpoBKU4VQKWrh2jnxRS2E1srhKF9p9
         nilf+24SXYxdmaOaqi10MgNNImpp6Lk/odio/8U7SIG+v/tTO7BqrPvbmGxyfJ163WlJ
         +pjPxe9Y5mKIKMwBuCCm2wgNTGpPqc6yH4y/LW9gwdzBGy85UbDyJ7HT8fne/9PLmFcI
         l/m9G7jEuHlQN7B+fpBGaYz+33e0tb+BLJoSCIiIT/Z5q2EqPSPQ16FQ62lNX+lde1Ke
         JqAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=XEvPLELH8ZJ3YaFyYH2vF7VUKzaFRnb24/rDbkj/y3I=;
        b=PSMCxW2kHzEkHesqjNwcuNptnFwmSfbm83ef4sEihao1CCAo+uzxhdHkeQiR5/HU8i
         3euj6Af0nIKukCc5eDTqt73SnVZhjlbl7f9uLKsF2F8qhhNl1hdouHnG/CESB9Zyn9SS
         l6dwOuPKEXF1hw+Xnk9JcMOi6FQnCxwXmfky5nJc4ozsdQNwmFnfIZXwmp/puhsKvOPf
         040FygGGGxWTeFsJVuNt2PCAtEYA5Od3TwaGTRpY2TRrk+pTQdxN/XpfOKx+EWfFd2jz
         akouVSEJCLz8X0tOnj6kWVQkx1gxa0h7uJ5ArtXt1Jtws0LV3bMyz1QRv0ZLzlf/qd+O
         3ptw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b="Mc3jfAM/";
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=cHBuKxiz;
       spf=pass (google.com: domain of 010101849ce195a5-6cf4a54f-95d0-42ae-99f3-dbba411cb545-000000@us-west-2.amazonses.com designates 54.240.27.55 as permitted sender) smtp.mailfrom=010101849ce195a5-6cf4a54f-95d0-42ae-99f3-dbba411cb545-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XEvPLELH8ZJ3YaFyYH2vF7VUKzaFRnb24/rDbkj/y3I=;
        b=Pzp1erY9JXFxVTkgQ/Mz4TgzeMgfnDLOoR/0lsuLwwOoRAmAKl7X3Qt08tgJSXLsZN
         I/kxzviIAyWzIqVtTDHDUSgMI3XYnQ0RVqkd44u8f68Jhhi/lTObxUGv2S4FNoZfHArX
         2Mj+4asGp+fTP59sRYSuNmIQkdMzo6uuye4uRY7BwGoevdq3XqXrd/IZSvniqRc44GZ3
         7e/RQL+X39Ebvfc1oBrWWhGkqwtT7DV7+dhEkoOvTzGGGrE2pClpZNeZM2LZ/BHiwdWQ
         c00H/tcdW01vglV+9BzWI4gCLv6lkT+qGruWGUsM211S1Vh7EuDmiWzeN6201w8qibxO
         fV4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=XEvPLELH8ZJ3YaFyYH2vF7VUKzaFRnb24/rDbkj/y3I=;
        b=tVRoL+nKYRzR9W5r3amrGsbgp70m1SAHQTjanYh1L1o5RiZAzvDA8+h971Dv8iJQlq
         tXi+6SVmVRjUqJH0sBqEYvRsqg5uLRq7g58Avf6+o5LAJBFPtUe+93VpBTLXHMcRh/KE
         QM91njQC508iIyGf9eCEx7zQvfOn6OOy1+QDMgOU/baQ6/eI8RfN9s2aJJT5rbE00cYC
         YDGmIq3qmENAPQsd6xV6hkxyWKwWmhhPsN+Nk8bUwJzAQoxWcmt96+UQFjWi/Ho+eUz+
         PbOC62ajBuVCuPkWgUe7OJqyIy6fZSfJkTqnnfP61LXW7OP0Gad6xA9droJEV/YFWx05
         ZjAA==
X-Gm-Message-State: ANoB5pl9tStPpKsI6Clx53ANnS6Jdv7htgDeOc+MMd4W/oCxJmXLn4dk
	8drskJHoAaHgt9wz5p2sK7I=
X-Google-Smtp-Source: AA0mqf4WC/hjTt0M65EVBzEoPPygKKEn9DHENnN25Uu02DicMKR9M6BXevXhPYHAPNy2KQZGs5kZLA==
X-Received: by 2002:a25:4183:0:b0:6ea:70f2:23d0 with SMTP id o125-20020a254183000000b006ea70f223d0mr1726390yba.123.1669079342410;
        Mon, 21 Nov 2022 17:09:02 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:9881:0:b0:367:447d:fe68 with SMTP id p123-20020a819881000000b00367447dfe68ls6237263ywg.3.-pod-prod-gmail;
 Mon, 21 Nov 2022 17:09:01 -0800 (PST)
X-Received: by 2002:a0d:d202:0:b0:370:1a06:1b4a with SMTP id u2-20020a0dd202000000b003701a061b4amr1667614ywd.206.1669079341748;
        Mon, 21 Nov 2022 17:09:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669079341; cv=none;
        d=google.com; s=arc-20160816;
        b=QDqP3uMvkELSsBwEPd8jrqArqQS/Tt1U4LizVaDYLLwyjThsta4EwWPI6KbdH62JW3
         9V7g2KlKxuX418fl8sbOOJtxPTmo4FuAIUB3Xk7V4PW9CUx140ngY8cI9QzJAKgY9eFO
         dsb4R/ofgYOlAvCjjmcOuZD2HUgc209Fc5SpU1cS+5uLbRzvPPHsrHEha3YP/S3RUTjK
         BNNO/PcABOwmGCUfB/WS/MdikxGJs3wtF+k13ciDIyL2zLYP2C0zDI8/DHxk5XVmbDkG
         fUslFY2vGSyqkFtCZNx8iyWCe8QLf0nfzePMzd+jkWv850Y7pyyt4ZZbNekF9UtdR7mp
         N/tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=8kaF8sTxcAEO8ROfXzgIl81glz2BiWnXBa0e+8pqh4o=;
        b=Q2wPnsFj2Kknnk3uXUtg9jr8e7ddfDxqBbmQzbvc0vsLG3KNQ/1hjFTHeTJQwT7Qy/
         oLY59+GgkwqMt1DHBPL8gEIK1yJ6C+XXPmGKkQknufiTpHWgoERSxkqT4q5trPgBdQMg
         p5xnV3UqOF4mUS8lncE2bKn8UxDbX7/t498n5iN8vKMIw2/Aamcn5HSnotEeKv4FO3Z4
         WosfRYP4fiu0O1jrFz5O6cLerjKynqPCH+Lsbl6sxuEy4tiBq31TvSrXXScA2AAyODk9
         CpGZGed7umpyJjJlLVG70gxjo/L1/QKNK9VNK6n96/I/YcOingJpiK6zun9iXocXee1u
         rZFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b="Mc3jfAM/";
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=cHBuKxiz;
       spf=pass (google.com: domain of 010101849ce195a5-6cf4a54f-95d0-42ae-99f3-dbba411cb545-000000@us-west-2.amazonses.com designates 54.240.27.55 as permitted sender) smtp.mailfrom=010101849ce195a5-6cf4a54f-95d0-42ae-99f3-dbba411cb545-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-55.smtp-out.us-west-2.amazonses.com (a27-55.smtp-out.us-west-2.amazonses.com. [54.240.27.55])
        by gmr-mx.google.com with ESMTPS id s196-20020a2577cd000000b006ddea715dd2si757067ybc.0.2022.11.21.17.09.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 17:09:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 010101849ce195a5-6cf4a54f-95d0-42ae-99f3-dbba411cb545-000000@us-west-2.amazonses.com designates 54.240.27.55 as permitted sender) client-ip=54.240.27.55;
Date: Tue, 22 Nov 2022 01:09:00 +0000
Message-ID: <010101849ce195a5-6cf4a54f-95d0-42ae-99f3-dbba411cb545-000000@us-west-2.amazonses.com>
To: bscattergood@roku.com, dmendenhall@roku.com, kcooper@roku.com,
        ksandvik@roku.com, mizhang@roku.com, najain@roku.com, pzhang@roku.com,
        sabellera@roku.com, snahibin@roku.com, tparker@roku.com
Cc: Alexander@localhost, Potapenko@localhost, glider@google.com,
        Dmitry@localhost, Vyukov@localhost, dvyukov@google.com,
        kasan-dev@googlegroups.com, Mike@localhost, Rapoport@localhost,
        rppt@linux.ibm.com
From: no-reply via kasan-dev <kasan-dev@googlegroups.com>
Reply-To: no-reply@roku.com ((Automation Account))
Subject: PERFORCE change 3224928: commit 328b6cddf9fe4ec86480d7eb7b46d35653781057
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.22-54.240.27.55
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b="Mc3jfAM/";       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=cHBuKxiz;       spf=pass
 (google.com: domain of 010101849ce195a5-6cf4a54f-95d0-42ae-99f3-dbba411cb545-000000@us-west-2.amazonses.com
 designates 54.240.27.55 as permitted sender) smtp.mailfrom=010101849ce195a5-6cf4a54f-95d0-42ae-99f3-dbba411cb545-000000@us-west-2.amazonses.com;
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

Change 3224928 by automation@source_control_dishonor on 2022/11/22 01:02:51

	commit 328b6cddf9fe4ec86480d7eb7b46d35653781057
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

.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/include/asm/kasan.h#1 add
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/include/asm/pgalloc.h#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/include/asm/thread_info.h#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/kernel/head-common.S#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/kernel/setup.c#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/mm/Makefile#3 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/mm/kasan_init.c#1 add
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/mm/pgd.c#2 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/include/asm/pgalloc.h#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/include/asm/thread_info.h#2 (text) ====

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
 

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/kernel/head-common.S#2 (text) ====

@@ -101,6 +101,9 @@
 	str	r2, [r6]			@ Save atags pointer
 	cmp	r7, #0
 	strne	r0, [r7]			@ Save control register values
+#ifdef CONFIG_KASAN
+	bl	kasan_early_init
+#endif
 	b	start_kernel
 ENDPROC(__mmap_switched)
 

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/kernel/setup.c#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/mm/Makefile#3 (text) ====

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

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/mm/pgd.c#2 (text) ====

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010101849ce195a5-6cf4a54f-95d0-42ae-99f3-dbba411cb545-000000%40us-west-2.amazonses.com.
