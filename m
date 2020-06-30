Return-Path: <kasan-dev+bncBDE6RCFOWIARBLUB5X3QKGQE57KZPBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id DC61E20F5E8
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 15:39:58 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id c25sf17015030edr.5
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 06:39:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593524398; cv=pass;
        d=google.com; s=arc-20160816;
        b=TNVJZKx3YJgAVXBM7bCEaMDmfTYFDQ9eNxgfi6z2HEqexQz1TJsJrpRuCctPYylZG9
         TBbY0u/uWemffnoBfPHauzAfd8vFxH7rX22sm1TguAMdDorH6B766EcBrdVic9W8Rn50
         MTdlCiv2ztBqbapkOclAeWv+WCB+yrCZQcwQe3FM+wlzYebV591XaS24JCn9eUS1I3il
         AD3WkmSN9FlFonIG774tVwrzAVZeR/NB7YUe6aX6liDzVOPwJ0IQUcO2lpVIp70xwuuE
         XczbyQnAF8IGQ9ESvBMQEGv7bbV1PAdK0XOMMB0Xdwb+Zol4a5EycaPwMX6NlBbuEz0l
         lqNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PXzNOM6xvt+gueHL6h6+stfMVuE9u5yIsnovn+XAnfw=;
        b=PGL0Y8nk8lD2SwSrW8CMV54m3UXK81TxrvpUYy6PoTomc0rpP3r2mSTs6l4KYikuZ7
         DCyHc7Pg8ymKeg7g6rcx5oWGUrSnaWw2m0BaURRagAF8zqxvTxFkl+UJjCvEA8SFZqrg
         3q4YfHyAi0tR/PfEZux0uFAtg4lVgKaibgIdrUoML0DmuYtJ88piSy7IOmol+GpwqPit
         b648lBrL1zAyGcu3mBjkzFb3jWOKd5asYaWaec32kf5aOS1x2g16SSKIWbki5Bkmh5FW
         /MGsqu4uIlzD6k8eSnGKu6s/cGVORnYyEpblJO8K55t+rxLU7br2cEjjxMT6weBAg7XJ
         jNiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=MQtsLvJC;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PXzNOM6xvt+gueHL6h6+stfMVuE9u5yIsnovn+XAnfw=;
        b=SEuCJBqhetKklJ3s2+kM97HESXl2XlgUxFRmtXDef0PSJMK+lfpxBYm4QP/FaeVU95
         atVeMRcisJDMIxy2sI+KjK3mtY/2HkQ3g0qFP62C6YrBfgSJbzFhErNct1hy3RrUbSth
         6f9B4mB5US2er/1YTOnUjr+TD+/mF70ACJCmCCbH6UUtTtOm4XDGYcZPpXGIdQVM+M7Y
         LOqVME09Zx9tel8UtR4WZ2NkEm/Zo7C8u94H3UxzmzvkK1w7LV424CXJB9U665DDMpLt
         t0WDsqw1SY9eoIt7zsfzfcnQkLIBcV9PjSxrPOmxliHw8ASM8iDeHhl0yu2r48O3GR58
         JBKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PXzNOM6xvt+gueHL6h6+stfMVuE9u5yIsnovn+XAnfw=;
        b=Fw+Z2sYGzEnfx13ScR6Og0jLEt4kArxsn6pPVlDjnNnxRdU/EHzeQC/HXnnJSUVMj8
         sq+VZKK79A0MmfaCcl/pGw1vg47IYATD6uNCj8TkVETf3eU+ktYaqO7izY/7jUTWPAeR
         5kkNJ64gc6LVSVNtIT5oVfY8NPA1Lh0yMNKDx9gyGZyliGgxrcnpuE3BCpBid1ePerWF
         b0MjBD1tuNLntp8ZR3sdHsT25cf/2blh/uOwydAUWcM3MJzS6nMm+xL/nmMcK8vwG6rt
         zvNs9V5gfd9lrSHfo55iPV5I7VOGkSp1nSNfp98rfT83Js17eSz8UIjrQnT5FhFodoZk
         ramw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZdRLrpom0stvuIrhPwU6Mo0biLn7RTzTjLwICoopCy1l0Rtoj
	LhtNWvolOd9AeGcBqf//8rk=
X-Google-Smtp-Source: ABdhPJyddmdaU+gxfeWSaHFNc8pOshgNM2LHw/B2BBwZPtKg2rZ1ISGqXwHQYBQYPTi/GBqRjSRgCA==
X-Received: by 2002:aa7:d2c9:: with SMTP id k9mr14966226edr.98.1593524398549;
        Tue, 30 Jun 2020 06:39:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:2cd2:: with SMTP id r18ls6414992ejr.9.gmail; Tue, 30
 Jun 2020 06:39:58 -0700 (PDT)
X-Received: by 2002:a17:906:c1c3:: with SMTP id bw3mr17342887ejb.8.1593524397977;
        Tue, 30 Jun 2020 06:39:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593524397; cv=none;
        d=google.com; s=arc-20160816;
        b=O7JIqeqrfy3mh39C/Jn1XgcW7e0zXa5P+lmiCfC1ZoPnOqBJjfH2TyAx7J/2F1SYvb
         9acqWrbmgPDRsRaHdent7RUN5GgFCQnBm2uTOmHEu7efl3RcgoJgWcNSZZFYcWb7u0vg
         UAAjESMe5Kj8AbWmMdEPPM1UNb+N9yTQQDpR4NAfuWFBGu6MvKfSoB3/FR556MPGA6sS
         AgyMi8Nmtb1fz/qRGPI5U/OwTfgGQrt/8fqGNwIqz9G5wRemNwuCBA6vH3PJJ9S59TRG
         xCcWjlDRC5ass+gcCKNC74vsa0XuKjpUtNZgEaeqNmEk8CGvZq6rLT8v/5qWdBytqpUJ
         uKFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ipV1AiQ3a/0fIXPK96a/jEMJ9Y2kEigvCjy/y24+aws=;
        b=rZO1YNAgSX3e2YOJxNMQhc83NUjmoZggnpEbuhHemyB7PEzbsmw7c/RoF2vCiMBehi
         j2n3ula7lD4iR9VNyOCotCa4tJ7FhGWrs7kVzK7HxpzsdPL/bkaj+q0qfbL+VSxMkhVa
         HLhVEVjKitShdsnMpHY8QXa6yycm6t0ZrXfbA82r9k8sju1X6gZwPGtBW0t58t6pPHj/
         L8cTDMyfteu8WVcAlSpX0GPvW1bwtCuM9xPKKzTRvyMNbN7ykqbFs2tOvTeX3XmExTOz
         +bdFpaZmOdw3UdQl6aaI7v2TWC0NU0VNVvNOVgn58aZuFtdaDT58GFgvA4ord7uqXbec
         Au2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=MQtsLvJC;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x144.google.com (mail-lf1-x144.google.com. [2a00:1450:4864:20::144])
        by gmr-mx.google.com with ESMTPS id x21si131505eju.0.2020.06.30.06.39.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jun 2020 06:39:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::144 as permitted sender) client-ip=2a00:1450:4864:20::144;
Received: by mail-lf1-x144.google.com with SMTP id m26so11405947lfo.13
        for <kasan-dev@googlegroups.com>; Tue, 30 Jun 2020 06:39:57 -0700 (PDT)
X-Received: by 2002:ac2:5ec9:: with SMTP id d9mr11999874lfq.58.1593524397285;
        Tue, 30 Jun 2020 06:39:57 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id a15sm737819ljn.105.2020.06.30.06.39.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jun 2020 06:39:56 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Mike Rapoport <rppt@linux.ibm.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Linus Walleij <linus.walleij@linaro.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH 4/5 v11] ARM: Initialize the mapping of KASan shadow memory
Date: Tue, 30 Jun 2020 15:37:35 +0200
Message-Id: <20200630133736.231220-5-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200630133736.231220-1-linus.walleij@linaro.org>
References: <20200630133736.231220-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=MQtsLvJC;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Cc: Mike Rapoport <rppt@linux.ibm.com>
Co-Developed-by: Abbott Liu <liuwenliang@huawei.com>
Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
Reported-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v10->v11:
- Fix compilation on LPAE systems.
- Move the check for valid pgdp, pudp and pmdp into the loop for
  each level moving over the directory pointers: we were just lucky
  that we just needed one directory for each level so this fixes
  the pmdp issue with LPAE and KASan now works like a charm on
  LPAE as well.
- Fold fourth level page directory (p4d) into the global page directory
  pgd and just skip into the page upper directory (pud) directly. We
  do not anticipate that ARM32 will every use 5-level page tables.
- Simplify the ifdeffery around the temporary pgd.
- Insert a comment about pud_populate() that is unconditionally called
  by the KASan core code.
ChangeLog v9->v10:
- Rebase onto v5.8-rc1
- add support for folded p4d page tables, use the primitives necessary
  for the 4th level folding, add (empty) walks of p4d level.
- Use the <linux/pgtable.h> header file that has now appeared as part
  of the VM consolidation series.
- Use a recursive method to walk pgd/p4d/pud/pmd/pte instead of the
  separate early/main calls and the flat call structure used in the
  old code. This was inspired by the ARM64 KASan init code.
- Assume authorship of this code, I have now written the majority of
  it so the blame is on me and noone else.
ChangeLog v8->v9:
- Drop the custom CP15 manipulation and cache flushing for swapping
  TTBR0 and instead just use cpu_switch_mm().
- Collect Ard's tags.
ChangeLog v7->v8:
- Rebased.
ChangeLog v6->v7:
- Use SPDX identifer for the license.
- Move the TTBR0 accessor calls into this patch.
---
 arch/arm/include/asm/kasan.h       |  32 ++++
 arch/arm/include/asm/pgalloc.h     |   8 +-
 arch/arm/include/asm/thread_info.h |   8 +
 arch/arm/kernel/head-common.S      |   3 +
 arch/arm/kernel/setup.c            |   2 +
 arch/arm/mm/Makefile               |   3 +
 arch/arm/mm/kasan_init.c           | 288 +++++++++++++++++++++++++++++
 arch/arm/mm/pgd.c                  |  16 +-
 8 files changed, 358 insertions(+), 2 deletions(-)
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
index 069da393110c..3bf1905df9c3 100644
--- a/arch/arm/include/asm/pgalloc.h
+++ b/arch/arm/include/asm/pgalloc.h
@@ -21,6 +21,7 @@
 #define _PAGE_KERNEL_TABLE	(PMD_TYPE_TABLE | PMD_BIT4 | PMD_DOMAIN(DOMAIN_KERNEL))
 
 #ifdef CONFIG_ARM_LPAE
+#define PGD_SIZE		(PTRS_PER_PGD * sizeof(pgd_t))
 
 static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
 {
@@ -39,14 +40,19 @@ static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
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
-
+#endif
 #endif	/* CONFIG_ARM_LPAE */
 
 extern pgd_t *pgd_alloc(struct mm_struct *mm);
diff --git a/arch/arm/include/asm/thread_info.h b/arch/arm/include/asm/thread_info.h
index 3609a6980c34..02813a5d9e10 100644
--- a/arch/arm/include/asm/thread_info.h
+++ b/arch/arm/include/asm/thread_info.h
@@ -13,7 +13,15 @@
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
index 000000000000..535dce42e59d
--- /dev/null
+++ b/arch/arm/mm/kasan_init.c
@@ -0,0 +1,288 @@
+// SPDX-License-Identifier: GPL-2.0-only
+/*
+ * This file contains kasan initialization code for ARM.
+ *
+ * Copyright (c) 2018 Samsung Electronics Co., Ltd.
+ * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
+ * Author: Linus Walleij <linus.walleij@linaro.org>
+ */
+
+#define pr_fmt(fmt) "kasan: " fmt
+#include <linux/kasan.h>
+#include <linux/kernel.h>
+#include <linux/memblock.h>
+#include <linux/sched/task.h>
+#include <linux/start_kernel.h>
+#include <linux/pgtable.h>
+#include <asm/cputype.h>
+#include <asm/highmem.h>
+#include <asm/mach/map.h>
+#include <asm/memory.h>
+#include <asm/page.h>
+#include <asm/pgalloc.h>
+#include <asm/procinfo.h>
+#include <asm/proc-fns.h>
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
+static void __init kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
+				      unsigned long end, int node, bool early)
+{
+	unsigned long next;
+	pte_t *ptep = pte_offset_kernel(pmdp, addr);
+
+	do {
+		next = addr + PAGE_SIZE;
+
+		if (pte_none(*ptep)) {
+			pte_t entry;
+			void *p;
+
+			/*
+			 * The early shadow memory is mapping all KASan operations to one and the same page
+			 * in memory, "kasan_early_shadow_page" so that the instrumentation will work on
+			 * a scratch area until we can set up the proper KASan shadow memory.
+			 */
+			if (early) {
+				p = kasan_early_shadow_page;
+				entry = pfn_pte(virt_to_pfn(kasan_early_shadow_page),
+						__pgprot(_L_PTE_DEFAULT | L_PTE_DIRTY
+							 | L_PTE_XN));
+			} else {
+				p = kasan_alloc_block(PAGE_SIZE, node);
+				if (!p) {
+					panic("%s failed to alloc pte for address 0x%lx\n",
+					      __func__, addr);
+					return;
+				}
+				memset(p, KASAN_SHADOW_INIT, PAGE_SIZE);
+				entry = pfn_pte(virt_to_pfn(p),
+					__pgprot(pgprot_val(PAGE_KERNEL)));
+			}
+
+			set_pte_at(&init_mm, addr, ptep, entry);
+		}
+	} while (ptep++, addr = next, addr != end && pte_none(READ_ONCE(*ptep)));
+}
+
+/*
+ * The pmd (page middle directory) used on LPAE?
+ */
+static void __init kasan_pmd_populate(pud_t *pudp, unsigned long addr,
+				      unsigned long end, int node, bool early)
+{
+	unsigned long next;
+	pmd_t *pmdp = pmd_offset(pudp, addr);
+
+	do {
+		if (pmd_none(*pmdp)) {
+			void *p = early ? kasan_early_shadow_pte : kasan_alloc_block(PAGE_SIZE, node);
+
+			if (!p) {
+				panic("%s failed to allocate pmd for address 0x%lx\n",
+				      __func__, addr);
+				return;
+			}
+			pmd_populate_kernel(&init_mm, pmdp, p);
+			flush_pmd_entry(pmdp);
+		}
+
+		next = pmd_addr_end(addr, end);
+		kasan_pte_populate(pmdp, addr, next, node, early);
+	} while (pmdp++, addr = next, addr != end && pmd_none(READ_ONCE(*pmdp)));
+}
+
+/*
+ * The pud (page upper directory) is only used on LPAE systems.
+ */
+static void __init kasan_pud_populate(p4d_t *p4dp, unsigned long addr,
+				      unsigned long end, int node, bool early)
+{
+	unsigned long next;
+	pud_t *pudp = pud_offset(p4dp, addr);
+
+	do {
+		/*
+		 * FIXME: necessary?
+		 * Allocate and populate the PUD if it doesn't already exist
+		 * On non-LPAE systems using just 2-level page tables pud_none()
+		 * will always be zero and this will be skipped.
+		 */
+		if (!early && pud_none(*pudp)) {
+			void *p = kasan_alloc_block(PAGE_SIZE, node);
+
+			if (!p) {
+				panic("%s failed to allocate pud for address 0x%lx\n",
+				      __func__, addr);
+				return;
+			}
+			if (IS_ENABLED(CONFIG_ARM_LPAE)) {
+				pr_info("populating pud addr %lx\n", addr);
+				pud_populate(&init_mm, pudp, p);
+			}
+		}
+
+		next = pud_addr_end(addr, end);
+		kasan_pmd_populate(pudp, addr, next, node, early);
+	} while (pudp++, addr = next, addr != end && pud_none(READ_ONCE(*pudp)));
+}
+
+static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
+				      int node, bool early)
+{
+	unsigned long next;
+	pgd_t *pgdp;
+	p4d_t *p4dp;
+
+	pgdp = pgd_offset_k(addr);
+
+	do {
+		/* Allocate and populate the PGD if it doesn't already exist */
+		if (!early && pgd_none(*pgdp)) {
+			void *p = kasan_alloc_block(PAGE_SIZE, node);
+
+			if (!p) {
+				panic("%s failed to allocate pgd for address 0x%lx\n",
+				      __func__, addr);
+				return;
+			}
+			pgd_populate(&init_mm, pgdp, p);
+		}
+
+		next = pgd_addr_end(addr, end);
+		/*
+		 * We just immediately jump over the p4p fourth level page
+		 * directory since we believe ARM32 will never gain four level
+		 * page tables.
+		 */
+		p4dp = p4d_offset(pgdp, addr);
+
+		kasan_pud_populate(p4dp, addr, next, node, early);
+	} while (pgdp++, addr = next, addr != end);
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
+	/*
+	 * We walk the page table and set all of the shadow memory to point
+	 * to the scratch page.
+	 */
+	kasan_pgd_populate(KASAN_SHADOW_START, KASAN_SHADOW_END, NUMA_NO_NODE,
+			   true);
+}
+
+static void __init clear_pgds(unsigned long start,
+			unsigned long end)
+{
+	for (; start && start < end; start += PMD_SIZE)
+		pmd_clear(pmd_off_k(start));
+}
+
+static int __init create_mapping(unsigned long start, unsigned long end,
+				int node)
+{
+	pr_info("populating shadow for %lx, %lx\n", start, end);
+	kasan_pgd_populate(start, end, NUMA_NO_NODE, false);
+	return 0;
+}
+
+void __init kasan_init(void)
+{
+	struct memblock_region *reg;
+	int i;
+
+	/*
+	 * We are going to perform proper setup of shadow memory.
+	 *
+	 * At first we should unmap early shadow (clear_pgds() call bellow).
+	 * However, instrumented code couldn't execute without shadow memory.
+	 *
+	 * To keep the early shadow memory MMU tables around while setting up
+	 * the proper shadow memory, we copy swapper_pg_dir (the initial page
+	 * table) to tmp_pgd_table and use that to keep the early shadow memory
+	 * mapped until the full shadow setup is finished. Then we swap back
+	 * to the proper swapper_pg_dir.
+	 */
+	memcpy(tmp_pgd_table, swapper_pg_dir, sizeof(tmp_pgd_table));
+#ifdef CONFIG_ARM_LPAE
+	memcpy(tmp_pmd_table,
+	       pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_START)),
+	       sizeof(tmp_pmd_table));
+	set_pgd(&tmp_pgd_table[pgd_index(KASAN_SHADOW_START)],
+		__pgd(__pa(tmp_pmd_table) | PMD_TYPE_TABLE | L_PGD_SWAPPER));
+#endif
+	cpu_switch_mm(tmp_pgd_table, &init_mm);
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
+	cpu_switch_mm(swapper_pg_dir, &init_mm);
+	pr_info("Kernel address sanitizer initialized\n");
+	init_task.kasan_depth = 0;
+}
diff --git a/arch/arm/mm/pgd.c b/arch/arm/mm/pgd.c
index c5e1b27046a8..f8e9bc58a84f 100644
--- a/arch/arm/mm/pgd.c
+++ b/arch/arm/mm/pgd.c
@@ -66,7 +66,21 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
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
2.25.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200630133736.231220-5-linus.walleij%40linaro.org.
