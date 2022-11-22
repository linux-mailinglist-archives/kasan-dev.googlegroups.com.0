Return-Path: <kasan-dev+bncBCJMBM5G5UCRBUFX6CNQMGQEGVHZ2NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 73E7E633188
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 01:46:10 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id p1-20020a17090a2c4100b00212733d7aaasf6677771pjm.4
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 16:46:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669077969; cv=pass;
        d=google.com; s=arc-20160816;
        b=mUtXKrJAqm3RdNM5q4kbytPKJsUDlD5RvDgTsKuMHhy8PF/weybfaneQq4mHc+/Rcx
         3SoX6Kj5si1biGZovHeMBVDW4pK0tf4x6XprGIZqVa/nJeLYTP8++VRG3V2jt97WtIdt
         /wJC/Cx0cn2CSXM41eu7P6BxKS4SHxyj5pREIGCncJ7MPNJBAabiN2hvAEE6jM+J8shH
         GOJxAmZCaLd0/bJtvWUrziLxljN5vBUv/LdxP1Ul0Wby3zyMedjLxpYR3DdfkyimNMwq
         r/aYWXITLd1ioy7EaF0EGDRNo+D7NsBGSUd3VQHPpZcqH4Mwya9Q17Fqba8NqWdUFdjD
         lRWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=vLtfjSmdW4qu3IqwhD1QVKYRvI+fUqHXxXEUOrvmDl4=;
        b=v7EMz9tXzfjElPQ9K18KUZyD7jFk/TibvNzmq6TT1v+ADYHQyWsvzTNVCoM9IzGl50
         Q+Lha05E2BHJXqoHbHbUv7zoP+J5JXN07VKtbwJYccgtxm2boHfZ/1/0a3rE/MIekeyC
         rwHd7X4S9581z7nhoizBklS2a19xxam+uzFjILxEXCuh+nMib2My+KjU4WOqgSqu3kVf
         JzMk4S0jK9JFl/d74HfnZn8LBVlYakz8SykTaQV8dctT9eOD8Fwhp+hgWZJ1mSME/S+D
         5z4xDRj3kb97VS+DgREZg7fN474YQt4eoXDqz5X6fnbhRm43HRCscMowv+j2l0DQOZh1
         U0Lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=ko0Fw5h2;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=AB9TcbCE;
       spf=pass (google.com: domain of 010101849ccca1f1-0e751e56-2da5-4a44-b318-72b801528f4a-000000@us-west-2.amazonses.com designates 54.240.27.186 as permitted sender) smtp.mailfrom=010101849ccca1f1-0e751e56-2da5-4a44-b318-72b801528f4a-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vLtfjSmdW4qu3IqwhD1QVKYRvI+fUqHXxXEUOrvmDl4=;
        b=HWP8OszzKxUML5W/nNZNsay5LUINTwtpnSEpQyVKF4sl8Z5T9qigX615TvPzFa3EC/
         o9irQ0/CE3FMmxYUNMID/+4RPThraDvtOTz0/DKn8MLufsl1J+U2fhDaI2ElZXrY2MbJ
         lIb3BU3bscVkCagG0i/m7nNiHqVgdurxBTtFmhVSiWQP5TLcABFd+MBsjHuguDiQHUOa
         PBd+Qi7eMhQsMxWLSA0LktlDhHvgq2bSB7cXW5pbl6E+PadDiqL3ElQAvSBzK2Eg4yVY
         ehwCVctEuzZ9RoxKOPLzpGj/l9wXBtrZSbWIyS5Np9zlfXT3RYKIwP8RksVZcdAWWYsR
         r3Cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=vLtfjSmdW4qu3IqwhD1QVKYRvI+fUqHXxXEUOrvmDl4=;
        b=UEnVJ8Yt/sxJsZbh0BEtsghGT4uuUJrGLQaTdBdFiX9dd4NS4dYnqeLaruOMSfTuZe
         BCYOCAxZoxMpzBuxT9RDLOSeY3MwqrOwiTPhvyaoFHdEjbgDV12B6iOp4tae4lJS5Bj/
         YN0qZ3lLi68ddFHcorld/g1ExtMZUb7rnYJf5Fh3FteVjMKvU93KCl7pjzm5hwPJW8ZY
         Sb0Lu7KGWWZtuOlz+P3qmoP44puxr0lKy51oihhtqcUv8JIlUJ8MH/OS0pcq9412CRjk
         CXkf62iLkius03t08HCqWpMqLqffLui1FkyfsWAZcHKid3zkrOwltKH45zkfQDSz4ioC
         OWig==
X-Gm-Message-State: ANoB5pmLjtrh83dAGRnfxUhRz3hSn2aZ9/gwEL2oo1eMLpebeewIT4ug
	pux04Yfp7/QbBcJvaLHks10=
X-Google-Smtp-Source: AA0mqf6sG1FLDKy8l/gPUQn30aOmTcL8EnafHWjuwwQqHaas1qcTh8LBI+s/MRaEDKcZjeg5PyETVg==
X-Received: by 2002:a17:902:ee89:b0:187:1a3f:d54b with SMTP id a9-20020a170902ee8900b001871a3fd54bmr14893558pld.9.1669077968889;
        Mon, 21 Nov 2022 16:46:08 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1c06:0:b0:561:e77b:c7c2 with SMTP id c6-20020a621c06000000b00561e77bc7c2ls6618881pfc.4.-pod-prod-gmail;
 Mon, 21 Nov 2022 16:46:08 -0800 (PST)
X-Received: by 2002:a63:c143:0:b0:45b:f8be:7400 with SMTP id p3-20020a63c143000000b0045bf8be7400mr1286561pgi.30.1669077968221;
        Mon, 21 Nov 2022 16:46:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669077968; cv=none;
        d=google.com; s=arc-20160816;
        b=woKMDWBiHTp7xOQP759eU6mIMOrwfxOjh1HQLXyGTdhlFCJLcggpiEAdloWl5Hw+Hi
         d5oHjQM1A1X1y6pt9Mh7sfBEAyTPOGyKvxL4E2myBssDNf09hm4Bc1sCIGexh7mhnaj9
         Mjc3i4uGFT9JSr3fpViCVW1tTbk+eaPexTl86owk+V1GpREgmZP1OpVPc7rBVnlsuDSl
         gehP7qowgetLAkqMVpA7Xt3yI/5tFqWRMV5rAN4zAvRqJsUyRGBtD+HgXfJgHVSm93Oa
         s4EwafWwwwGQAbK6OMi8P5JhcbGQUvwdb3A8278MqnLZTv82fHHGC6yQV0T2QQBMJFoC
         x8hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=0hZny99Sb6dTIiV0pnlrMgx86c9+h0c/M78wfBAxfRY=;
        b=Jsy36OKmilLYBeNTlPoqbeTF67ajwjlVji168NKsYvlkQ0bQI0xpfgCJC50k3J0xYb
         tIlWoERnp9wyIatymHPsRFPvU/vG1kz8Ykl/uE0EefNxU8D67IqRedVuAgmzWj8v+Ttf
         IatSRFuDa/hDyFnnTTkFh8rJkxI4bJzNjAmOPhal2r1P6oNPrVktVn9W20oz8qw5nWMP
         DCtaFle6ixt54q6iy65O7TMLb7jaIMScM6wfDyquhNZbBC/DQEfDb0NZiQxM/bBG5CmF
         MSDxmwG0GbdYQWvjby1dhETieeYZCRSCSNP9HmS1Qd8Z5Ibct64j8lazSvXblhRsdw1B
         h9qA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=ko0Fw5h2;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=AB9TcbCE;
       spf=pass (google.com: domain of 010101849ccca1f1-0e751e56-2da5-4a44-b318-72b801528f4a-000000@us-west-2.amazonses.com designates 54.240.27.186 as permitted sender) smtp.mailfrom=010101849ccca1f1-0e751e56-2da5-4a44-b318-72b801528f4a-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-186.smtp-out.us-west-2.amazonses.com (a27-186.smtp-out.us-west-2.amazonses.com. [54.240.27.186])
        by gmr-mx.google.com with ESMTPS id on16-20020a17090b1d1000b00213290fa218si646936pjb.2.2022.11.21.16.46.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 16:46:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 010101849ccca1f1-0e751e56-2da5-4a44-b318-72b801528f4a-000000@us-west-2.amazonses.com designates 54.240.27.186 as permitted sender) client-ip=54.240.27.186;
Date: Tue, 22 Nov 2022 00:46:07 +0000
Message-ID: <010101849ccca1f1-0e751e56-2da5-4a44-b318-72b801528f4a-000000@us-west-2.amazonses.com>
To: bscattergood@roku.com, dmendenhall@roku.com, kcooper@roku.com,
        ksandvik@roku.com, mizhang@roku.com, najain@roku.com, pzhang@roku.com,
        sabellera@roku.com, snahibin@roku.com, tparker@roku.com
Cc: Alexander@localhost, Potapenko@localhost, glider@google.com,
        Dmitry@localhost, Vyukov@localhost, dvyukov@google.com,
        kasan-dev@googlegroups.com, Mike@localhost, Rapoport@localhost,
        rppt@linux.ibm.com
From: no-reply via kasan-dev <kasan-dev@googlegroups.com>
Reply-To: no-reply@roku.com ((Automation Account))
Subject: PERFORCE change 3224912: commit 0724c61762f8f28435806dd1cfd189d47691ace2
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.22-54.240.27.186
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b=ko0Fw5h2;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=AB9TcbCE;       spf=pass
 (google.com: domain of 010101849ccca1f1-0e751e56-2da5-4a44-b318-72b801528f4a-000000@us-west-2.amazonses.com
 designates 54.240.27.186 as permitted sender) smtp.mailfrom=010101849ccca1f1-0e751e56-2da5-4a44-b318-72b801528f4a-000000@us-west-2.amazonses.com;
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

Change 3224912 by automation@vsergiienko-flipday-internal-rtd1395-nemo on 2022/11/22 00:40:20

	commit 0724c61762f8f28435806dd1cfd189d47691ace2
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

.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/include/asm/kasan.h#1 add
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/include/asm/pgalloc.h#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/include/asm/thread_info.h#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/kernel/head-common.S#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/kernel/setup.c#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/mm/Makefile#3 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/mm/kasan_init.c#1 add
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/mm/pgd.c#2 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/include/asm/pgalloc.h#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/include/asm/thread_info.h#2 (text) ====

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
 

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/kernel/head-common.S#2 (text) ====

@@ -101,6 +101,9 @@
 	str	r2, [r6]			@ Save atags pointer
 	cmp	r7, #0
 	strne	r0, [r7]			@ Save control register values
+#ifdef CONFIG_KASAN
+	bl	kasan_early_init
+#endif
 	b	start_kernel
 ENDPROC(__mmap_switched)
 

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/kernel/setup.c#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/mm/Makefile#3 (text) ====

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

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/mm/pgd.c#2 (text) ====

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010101849ccca1f1-0e751e56-2da5-4a44-b318-72b801528f4a-000000%40us-west-2.amazonses.com.
