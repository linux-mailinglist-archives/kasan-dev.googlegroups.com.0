Return-Path: <kasan-dev+bncBDE6RCFOWIARB7UG2D2QKGQEXD6HUIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C1071C8B48
	for <lists+kasan-dev@lfdr.de>; Thu,  7 May 2020 14:47:59 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id s12sf3310215wmj.6
        for <lists+kasan-dev@lfdr.de>; Thu, 07 May 2020 05:47:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588855678; cv=pass;
        d=google.com; s=arc-20160816;
        b=KeoSgXTHONIuXxya/c+cNreI9jfXCkVRyMj1oIKp5bK6C0wNDOqjmD98FAaZn/jbiM
         ErN7SODUMYtudoY2AJg6KlFO+m9tymQphprYjpy1eCoGzdSH7DWsugOKSZUwJQax8jDX
         nQOn7dSSfPIi42OfLwZEDTmWMh6CGzDih1SRZf9+7mO8GskUu8wgFj+q4iPpzORf7A18
         TyNMKhYRdlECoSEE4VZ0Y6LFo30Ie7mT3cw/p8Pfbj54mIr4WW5/OrNfLhQbObu0kHoe
         tBOGdHbacykye/6Al3Mpkg17c5YiFXeYsX26o1OOe8/cXBV987XSkTGM/EtUyYzGhk5Z
         ZkWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6qGAaVmQwZaoAVNhS1t4Claz2dCQpMikADS9Wbh3EhY=;
        b=lETZMcBVOjPoj9Zucyk6a6RbNAkU71yMv9ND1TDukCFlf/8t2q09P8Hh/pGnc7RXiy
         hm2zt8/bhduWehVF3wpQmXY4s/lE1hL1jgH0ZHm6LmEh6B/ZEQXEAyb1HEIuTI0KPiQI
         QJNmwgiPXHngv2Jw+qb1MTo9/02BVeZLwEL8Q9EcM1pQZ8GSv8v3vBUg77DEqolCuxtB
         PzyoVg4syT7X2XDcbYem1DF2qYUGSpOsKUBlSP63vTRHiDWFmiSYJtaA8WFio11p85dW
         X2R1eD/wp+VzL0vo2f6WaLssOWdLXSs30t9ozTTMMDSFLP7cfWif58RIzarY89cL2CSJ
         NUkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=nIP0wZeE;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6qGAaVmQwZaoAVNhS1t4Claz2dCQpMikADS9Wbh3EhY=;
        b=e6Ab25Y9rj9eVr7HaOa5MmbpOLkTlNdy8CZKK4JnSayF7vzXTB8WQhhy403CHtd3Es
         WP+ZPo3EzAf6NElTcyCuImjS83TSEBZXNEB+QEdQlGyq8sbTldtE5ItM9sTID3LBQKq4
         Z9puookDhGBsYcfLIxw9fLWcv9SCM8viCHiWslC8/EYJXKNIdeIbcoYEtegUEHnzjhq3
         tbepnBJGRSR6IYwJofvf8i8X4eUTDgu54vaMOPyff0+4JbqMHLh56ngkKgpYZZSTxZCb
         b8RcNPkQd4kMUCc2rr/fc7xgp6iNLCyHqcGYweQ8lzHD9VjRSB2YbV4Z7pEPW4gaYyvT
         JY6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6qGAaVmQwZaoAVNhS1t4Claz2dCQpMikADS9Wbh3EhY=;
        b=Ee/QaBDxcC5g/h93SsbQzJx4TkuQQYgUCgNvgZN1JPIWyBoZu/qBSv5qhRo6flaKB4
         SnBecIF++6S+DmCOWuyP611RCD+zMShquLiBzcc/OZ7jD6pSoqJ5TjhShX/gL2zEiJRT
         Ke7gjN0BZ3OnoehQEHMRwSsAYejsK0xxE6BgtRWa7H56CijUIw5/TjvaYADj/AgeMYr4
         CcobIqthxB2L9jw7j6QtlfMifjDtLDTbIlP80kocdFnaO/8ykc5K1Av9C021ppv7Tcek
         In1P8xB8QMQ93E1baXbHs1tQtLcG22fCzCNJVxpUYiNEyzlR5KBZW+kGdT6SAAtTUoFJ
         fwWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZnCaSVGNyOj5ENW+/srCtqsChwH+ip/yqabw436wRdWqZ8R7kE
	OQlwO0bsXknRkovdv6NVxvQ=
X-Google-Smtp-Source: APiQypKvx1MnNWdp4hod36ivFlBoZwHa3Sh+NHpMVPuPAGUuwMR2JuyDBlOd0vghiYX8LMEyUJvmaw==
X-Received: by 2002:a5d:4389:: with SMTP id i9mr16121251wrq.374.1588855678661;
        Thu, 07 May 2020 05:47:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7d92:: with SMTP id y140ls8359292wmc.2.gmail; Thu, 07
 May 2020 05:47:58 -0700 (PDT)
X-Received: by 2002:a1c:b445:: with SMTP id d66mr10633729wmf.187.1588855678171;
        Thu, 07 May 2020 05:47:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588855678; cv=none;
        d=google.com; s=arc-20160816;
        b=AGsPuSt1m7g2HXGKEK6lJkxz1XPa+bMFp/xlhVOqFS2tQ/2xDD/QTxXvW7efHtVnPK
         6BcBcjub76wpzdOpZv4Atp79qUAkLON3hYK0ecgjo9ktXHcBI71Nl35a2WQEVqEl5aNk
         HrP9DkkEQx8rvBFOoA5Ke3k2LkXBqnQp/jLg31YGocCQyeWG/iGOSmfiSbX4BulkhOYs
         XSZNwqy5M1Nqg7xKiveWt6lHwT8j6BW+/BnZVTUEozl4bPwwG5wIvAkKCFAGhACkOTN0
         jutuDTtUZrTmmNDs3BFhvs7K/V/dCPvItpCvOdPEEKufIgrdNGWGIGYAfibjN4MDw1sg
         //DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3H9iOQ4YeA15iUH3CkwdQdUIy9hqfmLHvN7UrcALcGg=;
        b=X1n09KZQWlI+l7P5PMN1bukMhqBd33nyR5jdlxfnOXFnMSHB7ACJzh9ToLPGUO36bm
         rajFHzYLi/YskIXxELEKblmVqo+gZ39JwG83CRFG04u0mka4XQ/ghxhlFYNLXM4w826O
         O1ynVOUE7ajRHHSmjmSmgqI3ym9gYr+w0BSIo6WNJOFSr/b9Q+lWWIeVd56lA0MMD/8y
         UgPrfZ9Nh4B+gOvHtQTiDWfgt17GRf+29J/XzS0gZFf6HJgEL+nJuP5txs3lPOkPR5wm
         bWMhfBGJFFxG/8xO72wEgKNyRCTk3ybmCKwYmgg+oxyrHjaPwxrwL6G7aKR2F8Em8rmJ
         lANQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=nIP0wZeE;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id u16si388690wmd.2.2020.05.07.05.47.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 May 2020 05:47:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id w20so6180195ljj.0
        for <kasan-dev@googlegroups.com>; Thu, 07 May 2020 05:47:58 -0700 (PDT)
X-Received: by 2002:a2e:b4e3:: with SMTP id s3mr2743763ljm.11.1588855677480;
        Thu, 07 May 2020 05:47:57 -0700 (PDT)
Received: from localhost.localdomain (c-f3d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.243])
        by smtp.gmail.com with ESMTPSA id b4sm3730126lfo.33.2020.05.07.05.47.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 May 2020 05:47:56 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 4/5 v8] ARM: Initialize the mapping of KASan shadow memory
Date: Thu,  7 May 2020 14:45:21 +0200
Message-Id: <20200507124522.171323-5-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200507124522.171323-1-linus.walleij@linaro.org>
References: <20200507124522.171323-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=nIP0wZeE;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

This patch initializes KASan shadow region's page table and memory.
There are two stage for KASan initializing:

1. At early boot stage the whole shadow region is mapped to just
   one physical page (kasan_zero_page). It is finished by the function
   kasan_early_init which is called by __mmap_switched(arch/arm/kernel/
   head-common.S)
             ---Andrey Ryabinin <aryabinin@virtuozzo.com>

2. After the calling of paging_init, we use kasan_zero_page as zero
   shadow for some memory that KASan does not need to track, and we
   allocate a new shadow space for the other memory that KASan need to
   track. These issues are finished by the function kasan_init which is
   call by setup_arch.
            ---Andrey Ryabinin <aryabinin@virtuozzo.com>

3. Add support ARM LPAE
   If LPAE is enabled, KASan shadow region's mapping table need be copied
   in the pgd_alloc() function.
            ---Abbott Liu <liuwenliang@huawei.com>

4. Change kasan_pte_populate,kasan_pmd_populate,kasan_pud_populate,
   kasan_pgd_populate from .meminit.text section to .init.text section.
           ---Reported by: Florian Fainelli <f.fainelli@gmail.com>
           ---Signed off by: Abbott Liu <liuwenliang@huawei.com>

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Co-Developed-by: Abbott Liu <liuwenliang@huawei.com>
Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
Reported-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v7->v8:
- Rebased.
ChangeLog v6->v7:
- Use SPDX identifer for the license.
- Move the TTBR0 accessor calls into this patch.
---
 arch/arm/include/asm/kasan.h       |  32 +++
 arch/arm/include/asm/pgalloc.h     |   9 +-
 arch/arm/include/asm/thread_info.h |   4 +
 arch/arm/kernel/head-common.S      |   3 +
 arch/arm/kernel/setup.c            |   2 +
 arch/arm/mm/Makefile               |   3 +
 arch/arm/mm/kasan_init.c           | 324 +++++++++++++++++++++++++++++
 arch/arm/mm/pgd.c                  |  15 +-
 8 files changed, 389 insertions(+), 3 deletions(-)
 create mode 100644 arch/arm/include/asm/kasan.h
 create mode 100644 arch/arm/mm/kasan_init.c

diff --git a/arch/arm/include/asm/kasan.h b/arch/arm/include/asm/kasan.h
new file mode 100644
index 000000000000..56b954db160e
--- /dev/null
+++ b/arch/arm/include/asm/kasan.h
@@ -0,0 +1,32 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * arch/arm/include/asm/kasan.h
+ *
+ * Copyright (c) 2015 Samsung Electronics Co., Ltd.
+ * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
+ *
+ */
+
+#ifndef __ASM_KASAN_H
+#define __ASM_KASAN_H
+
+#ifdef CONFIG_KASAN
+
+#include <asm/kasan_def.h>
+
+#define KASAN_SHADOW_SCALE_SHIFT 3
+
+/*
+ * The compiler uses a shadow offset assuming that addresses start
+ * from 0. Kernel addresses don't start from 0, so shadow
+ * for kernel really starts from 'compiler's shadow offset' +
+ * ('kernel address space start' >> KASAN_SHADOW_SCALE_SHIFT)
+ */
+
+extern void kasan_init(void);
+
+#else
+static inline void kasan_init(void) { }
+#endif
+
+#endif
diff --git a/arch/arm/include/asm/pgalloc.h b/arch/arm/include/asm/pgalloc.h
index 069da393110c..d969f8058b26 100644
--- a/arch/arm/include/asm/pgalloc.h
+++ b/arch/arm/include/asm/pgalloc.h
@@ -21,6 +21,7 @@
 #define _PAGE_KERNEL_TABLE	(PMD_TYPE_TABLE | PMD_BIT4 | PMD_DOMAIN(DOMAIN_KERNEL))
 
 #ifdef CONFIG_ARM_LPAE
+#define PGD_SIZE		(PTRS_PER_PGD * sizeof(pgd_t))
 
 static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
 {
@@ -39,14 +40,18 @@ static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
 }
 
 #else	/* !CONFIG_ARM_LPAE */
+#define PGD_SIZE		(PAGE_SIZE << 2)
 
 /*
  * Since we have only two-level page tables, these are trivial
  */
 #define pmd_alloc_one(mm,addr)		({ BUG(); ((pmd_t *)2); })
 #define pmd_free(mm, pmd)		do { } while (0)
-#define pud_populate(mm,pmd,pte)	BUG()
-
+#ifndef CONFIG_KASAN
+#define pud_populate(mm, pmd, pte)	BUG()
+#else
+#define pud_populate(mm, pmd, pte)	do { } while (0)
+#endif
 #endif	/* CONFIG_ARM_LPAE */
 
 extern pgd_t *pgd_alloc(struct mm_struct *mm);
diff --git a/arch/arm/include/asm/thread_info.h b/arch/arm/include/asm/thread_info.h
index 3609a6980c34..cf47cf9c4742 100644
--- a/arch/arm/include/asm/thread_info.h
+++ b/arch/arm/include/asm/thread_info.h
@@ -13,7 +13,11 @@
 #include <asm/fpstate.h>
 #include <asm/page.h>
 
+#ifdef CONFIG_KASAN
+#define THREAD_SIZE_ORDER	2
+#else
 #define THREAD_SIZE_ORDER	1
+#endif
 #define THREAD_SIZE		(PAGE_SIZE << THREAD_SIZE_ORDER)
 #define THREAD_START_SP		(THREAD_SIZE - 8)
 
diff --git a/arch/arm/kernel/head-common.S b/arch/arm/kernel/head-common.S
index 6840c7c60a85..89c80154b9ef 100644
--- a/arch/arm/kernel/head-common.S
+++ b/arch/arm/kernel/head-common.S
@@ -111,6 +111,9 @@ __mmap_switched:
 	str	r8, [r2]			@ Save atags pointer
 	cmp	r3, #0
 	strne	r10, [r3]			@ Save control register values
+#ifdef CONFIG_KASAN
+	bl	kasan_early_init
+#endif
 	mov	lr, #0
 	b	start_kernel
 ENDPROC(__mmap_switched)
diff --git a/arch/arm/kernel/setup.c b/arch/arm/kernel/setup.c
index d8e18cdd96d3..b0820847bb92 100644
--- a/arch/arm/kernel/setup.c
+++ b/arch/arm/kernel/setup.c
@@ -58,6 +58,7 @@
 #include <asm/unwind.h>
 #include <asm/memblock.h>
 #include <asm/virt.h>
+#include <asm/kasan.h>
 
 #include "atags.h"
 
@@ -1130,6 +1131,7 @@ void __init setup_arch(char **cmdline_p)
 	early_ioremap_reset();
 
 	paging_init(mdesc);
+	kasan_init();
 	request_standard_resources(mdesc);
 
 	if (mdesc->restart)
diff --git a/arch/arm/mm/Makefile b/arch/arm/mm/Makefile
index 99699c32d8a5..4536159bc8fa 100644
--- a/arch/arm/mm/Makefile
+++ b/arch/arm/mm/Makefile
@@ -113,3 +113,6 @@ obj-$(CONFIG_CACHE_L2X0_PMU)	+= cache-l2x0-pmu.o
 obj-$(CONFIG_CACHE_XSC3L2)	+= cache-xsc3l2.o
 obj-$(CONFIG_CACHE_TAUROS2)	+= cache-tauros2.o
 obj-$(CONFIG_CACHE_UNIPHIER)	+= cache-uniphier.o
+
+KASAN_SANITIZE_kasan_init.o	:= n
+obj-$(CONFIG_KASAN)		+= kasan_init.o
diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
new file mode 100644
index 000000000000..043b4f33380e
--- /dev/null
+++ b/arch/arm/mm/kasan_init.c
@@ -0,0 +1,324 @@
+// SPDX-License-Identifier: GPL-2.0-only
+/*
+ * This file contains kasan initialization code for ARM.
+ *
+ * Copyright (c) 2018 Samsung Electronics Co., Ltd.
+ * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
+ */
+
+#define pr_fmt(fmt) "kasan: " fmt
+#include <linux/kasan.h>
+#include <linux/kernel.h>
+#include <linux/memblock.h>
+#include <linux/sched/task.h>
+#include <linux/start_kernel.h>
+#include <asm/cputype.h>
+#include <asm/highmem.h>
+#include <asm/mach/map.h>
+#include <asm/memory.h>
+#include <asm/page.h>
+#include <asm/pgalloc.h>
+#include <asm/pgtable.h>
+#include <asm/procinfo.h>
+#include <asm/proc-fns.h>
+#include <asm/tlbflush.h>
+#include <asm/cp15.h>
+
+#include "mm.h"
+
+static pgd_t tmp_pgd_table[PTRS_PER_PGD] __initdata __aligned(PGD_SIZE);
+
+pmd_t tmp_pmd_table[PTRS_PER_PMD] __page_aligned_bss;
+
+static __init void *kasan_alloc_block(size_t size, int node)
+{
+	return memblock_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
+				      MEMBLOCK_ALLOC_KASAN, node);
+}
+
+static void __init kasan_early_pmd_populate(unsigned long start,
+					unsigned long end, pud_t *pud)
+{
+	unsigned long addr;
+	unsigned long next;
+	pmd_t *pmd;
+
+	pmd = pmd_offset(pud, start);
+	for (addr = start; addr < end;) {
+		pmd_populate_kernel(&init_mm, pmd, kasan_early_shadow_pte);
+		next = pmd_addr_end(addr, end);
+		addr = next;
+		flush_pmd_entry(pmd);
+		pmd++;
+	}
+}
+
+static void __init kasan_early_pud_populate(unsigned long start,
+				unsigned long end, pgd_t *pgd)
+{
+	unsigned long addr;
+	unsigned long next;
+	pud_t *pud;
+
+	pud = pud_offset(pgd, start);
+	for (addr = start; addr < end;) {
+		next = pud_addr_end(addr, end);
+		kasan_early_pmd_populate(addr, next, pud);
+		addr = next;
+		pud++;
+	}
+}
+
+void __init kasan_map_early_shadow(pgd_t *pgdp)
+{
+	int i;
+	unsigned long start = KASAN_SHADOW_START;
+	unsigned long end = KASAN_SHADOW_END;
+	unsigned long addr;
+	unsigned long next;
+	pgd_t *pgd;
+
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		set_pte_at(&init_mm, KASAN_SHADOW_START + i*PAGE_SIZE,
+			&kasan_early_shadow_pte[i], pfn_pte(
+				virt_to_pfn(kasan_early_shadow_page),
+				__pgprot(_L_PTE_DEFAULT | L_PTE_DIRTY
+					| L_PTE_XN)));
+
+	pgd = pgd_offset_k(start);
+	for (addr = start; addr < end;) {
+		next = pgd_addr_end(addr, end);
+		kasan_early_pud_populate(addr, next, pgd);
+		addr = next;
+		pgd++;
+	}
+}
+
+extern struct proc_info_list *lookup_processor_type(unsigned int);
+
+void __init kasan_early_init(void)
+{
+	struct proc_info_list *list;
+
+	/*
+	 * locate processor in the list of supported processor
+	 * types.  The linker builds this table for us from the
+	 * entries in arch/arm/mm/proc-*.S
+	 */
+	list = lookup_processor_type(read_cpuid_id());
+	if (list) {
+#ifdef MULTI_CPU
+		processor = *list->proc;
+#endif
+	}
+
+	BUILD_BUG_ON((KASAN_SHADOW_END - (1UL << 29)) != KASAN_SHADOW_OFFSET);
+	kasan_map_early_shadow(swapper_pg_dir);
+}
+
+static void __init clear_pgds(unsigned long start,
+			unsigned long end)
+{
+	for (; start && start < end; start += PMD_SIZE)
+		pmd_clear(pmd_off_k(start));
+}
+
+pte_t * __init kasan_pte_populate(pmd_t *pmd, unsigned long addr, int node)
+{
+	pte_t *pte = pte_offset_kernel(pmd, addr);
+
+	if (pte_none(*pte)) {
+		pte_t entry;
+		void *p = kasan_alloc_block(PAGE_SIZE, node);
+
+		if (!p)
+			return NULL;
+		entry = pfn_pte(virt_to_pfn(p),
+			__pgprot(pgprot_val(PAGE_KERNEL)));
+		set_pte_at(&init_mm, addr, pte, entry);
+	}
+	return pte;
+}
+
+pmd_t * __init kasan_pmd_populate(pud_t *pud, unsigned long addr, int node)
+{
+	pmd_t *pmd = pmd_offset(pud, addr);
+
+	if (pmd_none(*pmd)) {
+		void *p = kasan_alloc_block(PAGE_SIZE, node);
+
+		if (!p)
+			return NULL;
+		pmd_populate_kernel(&init_mm, pmd, p);
+	}
+	return pmd;
+}
+
+pud_t * __init kasan_pud_populate(pgd_t *pgd, unsigned long addr, int node)
+{
+	pud_t *pud = pud_offset(pgd, addr);
+
+	/*
+	 * On non-LPAE systems using just 2-level page tables pud_none()
+	 * will alwats be zero and we bail out of here.
+	 */
+	if (pud_none(*pud)) {
+		void *p = kasan_alloc_block(PAGE_SIZE, node);
+
+		if (!p)
+			return NULL;
+		pr_err("populating pud addr %lx\n", addr);
+		pud_populate(&init_mm, pud, p);
+	}
+	return pud;
+}
+
+pgd_t * __init kasan_pgd_populate(unsigned long addr, int node)
+{
+	pgd_t *pgd = pgd_offset_k(addr);
+
+	if (pgd_none(*pgd)) {
+		void *p = kasan_alloc_block(PAGE_SIZE, node);
+
+		if (!p)
+			return NULL;
+		pgd_populate(&init_mm, pgd, p);
+	}
+	return pgd;
+}
+
+static int __init create_mapping(unsigned long start, unsigned long end,
+				int node)
+{
+	unsigned long addr = start;
+	pgd_t *pgd;
+	pud_t *pud;
+	pmd_t *pmd;
+	pte_t *pte;
+
+	pr_info("populating shadow for %lx, %lx\n", start, end);
+
+	for (; addr < end; addr += PAGE_SIZE) {
+		pgd = kasan_pgd_populate(addr, node);
+		if (!pgd)
+			return -ENOMEM;
+
+		pud = kasan_pud_populate(pgd, addr, node);
+		if (!pud)
+			return -ENOMEM;
+
+		pmd = kasan_pmd_populate(pud, addr, node);
+		if (!pmd)
+			return -ENOMEM;
+
+		pte = kasan_pte_populate(pmd, addr, node);
+		if (!pte)
+			return -ENOMEM;
+	}
+	return 0;
+}
+
+/*
+ * TTBR0 accessors
+ */
+#define TTBR0_32	__ACCESS_CP15(c2, 0, c0, 0)
+#define TTBR0_64	__ACCESS_CP15_64(0, c2)
+
+static inline void set_ttbr0(u64 val)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		write_sysreg(val, TTBR0_64);
+	else
+		write_sysreg(val, TTBR0_32);
+}
+
+static inline u64 get_ttbr0(void)
+{
+	if (IS_ENABLED(CONFIG_ARM_LPAE))
+		return read_sysreg(TTBR0_64);
+	else
+		return read_sysreg(TTBR0_32);
+}
+
+void __init kasan_init(void)
+{
+	struct memblock_region *reg;
+	u64 orig_ttbr0;
+	int i;
+
+	/*
+	 * We are going to perform proper setup of shadow memory.
+	 *
+	 * At first we should unmap early shadow (clear_pgds() call bellow).
+	 * However, instrumented code couldn't execute without shadow memory.
+	 * tmp_pgd_table and tmp_pmd_table used to keep the early shadow memory
+	 * mapped until the full shadow setup is finished.
+	 */
+	orig_ttbr0 = get_ttbr0();
+
+#ifdef CONFIG_ARM_LPAE
+	memcpy(tmp_pmd_table,
+		pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_START)),
+		sizeof(tmp_pmd_table));
+	memcpy(tmp_pgd_table, swapper_pg_dir, sizeof(tmp_pgd_table));
+	set_pgd(&tmp_pgd_table[pgd_index(KASAN_SHADOW_START)],
+		__pgd(__pa(tmp_pmd_table) | PMD_TYPE_TABLE | L_PGD_SWAPPER));
+	set_ttbr0(__pa(tmp_pgd_table));
+#else
+	memcpy(tmp_pgd_table, swapper_pg_dir, sizeof(tmp_pgd_table));
+	set_ttbr0((u64)__pa(tmp_pgd_table));
+#endif
+	flush_cache_all();
+	local_flush_bp_all();
+	local_flush_tlb_all();
+
+	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
+
+	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
+				    kasan_mem_to_shadow((void *)-1UL) + 1);
+
+	for_each_memblock(memory, reg) {
+		void *start = __va(reg->base);
+		void *end = __va(reg->base + reg->size);
+
+		if (reg->base + reg->size > arm_lowmem_limit)
+			end = __va(arm_lowmem_limit);
+		if (start >= end)
+			break;
+
+		create_mapping((unsigned long)kasan_mem_to_shadow(start),
+			(unsigned long)kasan_mem_to_shadow(end),
+			NUMA_NO_NODE);
+	}
+
+	/*
+	 * 1. The module global variables are in MODULES_VADDR ~ MODULES_END,
+	 *    so we need to map this area.
+	 * 2. PKMAP_BASE ~ PKMAP_BASE+PMD_SIZE's shadow and MODULES_VADDR
+	 *    ~ MODULES_END's shadow is in the same PMD_SIZE, so we can't
+	 *    use kasan_populate_zero_shadow.
+	 */
+	create_mapping(
+		(unsigned long)kasan_mem_to_shadow((void *)MODULES_VADDR),
+		(unsigned long)kasan_mem_to_shadow((void *)(PKMAP_BASE +
+							PMD_SIZE)),
+		NUMA_NO_NODE);
+
+	/*
+	 * KAsan may reuse the contents of kasan_early_shadow_pte directly, so
+	 * we should make sure that it maps the zero page read-only.
+	 */
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		set_pte_at(&init_mm, KASAN_SHADOW_START + i*PAGE_SIZE,
+			&kasan_early_shadow_pte[i],
+			pfn_pte(virt_to_pfn(kasan_early_shadow_page),
+				__pgprot(pgprot_val(PAGE_KERNEL)
+					| L_PTE_RDONLY)));
+	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+	set_ttbr0(orig_ttbr0);
+	flush_cache_all();
+	local_flush_bp_all();
+	local_flush_tlb_all();
+	pr_info("Kernel address sanitizer initialized\n");
+	init_task.kasan_depth = 0;
+}
diff --git a/arch/arm/mm/pgd.c b/arch/arm/mm/pgd.c
index 478bd2c6aa50..3a25c3fa6a92 100644
--- a/arch/arm/mm/pgd.c
+++ b/arch/arm/mm/pgd.c
@@ -61,7 +61,20 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
 	new_pmd = pmd_alloc(mm, new_pud, 0);
 	if (!new_pmd)
 		goto no_pmd;
-#endif
+#ifdef CONFIG_KASAN
+	/*
+	 * Copy PMD table for KASAN shadow mappings.
+	 */
+	init_pgd = pgd_offset_k(TASK_SIZE);
+	init_pud = pud_offset(init_pgd, TASK_SIZE);
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
2.25.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200507124522.171323-5-linus.walleij%40linaro.org.
