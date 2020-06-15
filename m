Return-Path: <kasan-dev+bncBDE6RCFOWIARBPXTTT3QKGQEZCMDMKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id F17181F92A7
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 11:05:02 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id k12sf4852301lfg.7
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 02:05:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592211902; cv=pass;
        d=google.com; s=arc-20160816;
        b=USQWmksjzu+5k++Frdmhgs2VZ1ClnrmWAJS6jkwKiAbooUuzAPU9r3D311OYGKgqhv
         ZH/3AzyuPkK2i2Vxk9FTIVgLLhXwi/JgrWjjHUxByDF5iffPad16pTk2B1WKONhWZREQ
         WnIvQAHjDCfwunOGcK25h5AKnFzZK9uIfHwBY1rVi+k2XuScjnXEF5QAvxfRRlsiRN5M
         mSd3FrQU9a9rGVchlJRvW6MMBc6SfW7uPUcvSo2XuS0f8jiD/sOrpHcFQXl7XLkjK193
         fvAqMoGWhsgufI/rse18xUF68GJpo7rj4nh5zfdWSLRgvKPt6FLM0oF6cS2LAtoNcz8U
         WqlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=959xwHFcXEmeA7xn+qDeoS/Cu1pr2IGzqNDEQZqzdrk=;
        b=KgzGI+CsnOaK4wtW6NFuO1bpJ+H+l2GIdDHg+y7erUbmX7axOm+3WR2zdFqEAbgac7
         KFDXjE0/84D2GVEKX9XH6dRxxudEE6AiSrps724SETFjW0HSjJLyaWt/LlnReJgBikjo
         XdGsueKpFjKnwW/jd6qo4rEw2RzoKE3Tm8QUWQsdxeG/vgkfgAsUXN5Tud8coYLKb1+0
         gbPl2ckSFjAGdMLOWil+y+CaTl4794vppt3BAF28fR2qUiRf+K7vd8hfHCUFFy8puK6z
         fTHLB5orybIu45DPQXr+9O+wNm1bVTphz65iEdXHvQNXXHumM9qq5GkDeiimqLYbagpW
         hjTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=aecswP22;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=959xwHFcXEmeA7xn+qDeoS/Cu1pr2IGzqNDEQZqzdrk=;
        b=mw4TDB974raDvFN8crte2lkcfgWhlxPnLBJMyrii2NFgN+N1WL5VYuiZOav43fs4me
         y7yrw+XTUbF7cjgWan9WPO4nMXmpQZ3wcEmulNUX3sDzeXlotP7RnOu8rLryb2hgNh/b
         nvC8ggmqlYl0BXZItqWq3B8yteLeI+SLbU1OCXbqjnW1lM/xtF7LXFBgUeeIlPDNmOYt
         3OqT+fvNaiDWD4K5XRzOULVk13x2mn2wvCb1wwPjbNmL/OREX4Q3kMh+6OSozMn5rp9z
         nwBwJ8grrF9qPO+HQxzTAbfH3Lcjr8sD4fVDkrl2lwPfjP90nCYYaDmyVexlxZ800zFA
         GtOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=959xwHFcXEmeA7xn+qDeoS/Cu1pr2IGzqNDEQZqzdrk=;
        b=dm5ck265bHcwz/A/3JM69/POBlyT8U9LqVZ2J6LpKknKvkqyXPAzuylK7rYSlu/hci
         i+yg4Xs8IYMAVA19GrOB7zbYowgR3Iq591n+CTaJ70SOj83fualaRu2TIIPjVuxOXgoK
         UWSl248J7Q2DTJ5hCY5GGksjkDhRaDHQaSLdjYeUCEDbzUbafr8Q+cXuCus2TyZBxenm
         LGqz5Emgj655P6Igx8M9cQel3zluZSNPjFZjZI0AunENcp0RjQ+DHIxeLGSBZ9w20c6f
         L8Vkl67r/hAj7DWVThj0FWZKwY7oqmGyecSKr51EB89BBwDv4RQg6lVajsyQxKTNUUs8
         J0IA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532j/uIcbv7TJc9SDaqXs5Pkr6sJx0/x7R8CfrXFwHqrwjDztaBf
	oIfTyGtCMxel8cYHch2bYF4=
X-Google-Smtp-Source: ABdhPJwez7pZyf+1ZXdlg+6WNsVflHLqYRXKx4ZOEZY6pvn2sj/xvAdSqpaQKW+W1F1UDAwGxtqNyw==
X-Received: by 2002:a2e:800b:: with SMTP id j11mr13612677ljg.467.1592211902357;
        Mon, 15 Jun 2020 02:05:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:92d6:: with SMTP id k22ls2456410ljh.4.gmail; Mon, 15 Jun
 2020 02:05:01 -0700 (PDT)
X-Received: by 2002:a2e:911:: with SMTP id 17mr13220890ljj.411.1592211901747;
        Mon, 15 Jun 2020 02:05:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592211901; cv=none;
        d=google.com; s=arc-20160816;
        b=oy2H/5MdAT+rgYCxTVxwT6Xub7CgQ6hFPlpimqxTBiiepUZNPhG+CjO5QGRMcCwu3K
         tLHrmvWXW7emY3YEgUCyqufUXteOmzGhZH7dbhwXvlZjoAp21hDacHrHJKaVn2oXgSjn
         GyjxuDNZc4Gsnq5jAqrmfoBgvGMtnMxTy8m0CpYyWumNwnoNv0nHB0BuMc6gn0cS9r3D
         R7qJPzjf9WjDEBHhla4yiGGJDJxgFfJEDBpimpa6nx9bbK2bBoXnZ3r338VqMeDpGTwz
         /oXtP+71pcwqtOWaMpJtjnQncavr8fzDA+8pAyjhd8ylrrsG3/HHBLl3+N6L42U1OMrr
         sPlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AVIqAVowCMkKmTiihEes5/dU7jVqd1QwevHRtqn290w=;
        b=U8ShZkPrauizi2CgcTJx0FnFJVKgSlOH769hTy/V2F87f67xsmBIQ9ItHwZlCdjIDp
         tA3YF9VT0f3PP5YRHNaHVIKqdIbCZK8k+hXoqu1tVwoapGSV0ydLZEcSwpIMafgTQIOq
         DpdhupXCnwyjmKZeQ5SbRcWwbP9hAbdTiVJCdtfQURdGIXaX3/14v6jZ3EmgCEQiJZAU
         8s/1oKDNwyIAw3pETBNZwB+JQ/wOAuQ60NpP1gD1kyuOfdfXLTievYtaKWwjficXwUNY
         9JxECzrKiWp+0dKDcQI3NWA5OfCKGjfBrTG7X45iJUchdCELItLgSWBTOgndXF/DjedJ
         wLRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=aecswP22;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id z3si123982lfe.5.2020.06.15.02.05.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jun 2020 02:05:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id 9so18246947ljc.8
        for <kasan-dev@googlegroups.com>; Mon, 15 Jun 2020 02:05:01 -0700 (PDT)
X-Received: by 2002:a2e:140a:: with SMTP id u10mr12358777ljd.56.1592211901222;
        Mon, 15 Jun 2020 02:05:01 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id c78sm5284434lfd.63.2020.06.15.02.05.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 02:05:00 -0700 (PDT)
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
Subject: [PATCH 4/5 v10] ARM: Initialize the mapping of KASan shadow memory
Date: Mon, 15 Jun 2020 11:02:46 +0200
Message-Id: <20200615090247.5218-5-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200615090247.5218-1-linus.walleij@linaro.org>
References: <20200615090247.5218-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=aecswP22;       spf=pass
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
  sequence to be recursive based on ARM64:s kasan_init.c

Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
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
 arch/arm/include/asm/kasan.h       |  32 +++
 arch/arm/include/asm/pgalloc.h     |   9 +-
 arch/arm/include/asm/thread_info.h |   4 +
 arch/arm/kernel/head-common.S      |   3 +
 arch/arm/kernel/setup.c            |   2 +
 arch/arm/mm/Makefile               |   3 +
 arch/arm/mm/kasan_init.c           | 304 +++++++++++++++++++++++++++++
 arch/arm/mm/pgd.c                  |  15 +-
 8 files changed, 369 insertions(+), 3 deletions(-)
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
index 000000000000..6438a13f8368
--- /dev/null
+++ b/arch/arm/mm/kasan_init.c
@@ -0,0 +1,304 @@
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
+	if (pmd_none(*pmdp)) {
+		void *p = early ? kasan_early_shadow_pte : kasan_alloc_block(PAGE_SIZE, node);
+
+		if (!p) {
+			panic("%s failed to allocate pmd for address 0x%lx\n",
+			      __func__, addr);
+			return;
+		}
+		pmd_populate_kernel(&init_mm, pmdp, p);
+		flush_pmd_entry(pmdp);
+	}
+
+	do {
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
+	/*
+	 * FIXME: necessary?
+	 * Allocate and populate the PUD if it doesn't already exist
+	 * On non-LPAE systems using just 2-level page tables pud_none()
+	 * will always be zero and this will be skipped.
+	 */
+	if (!early && pud_none(*pudp)) {
+		void *p = kasan_alloc_block(PAGE_SIZE, node);
+
+		if (!p) {
+			panic("%s failed to allocate pud for address 0x%lx\n",
+			      __func__, addr);
+			return;
+		}
+		pr_info("populating pud addr %lx\n", addr);
+		pud_populate(&init_mm, pudp, p);
+	}
+
+	do {
+		next = pud_addr_end(addr, end);
+		kasan_pmd_populate(pudp, addr, next, node, early);
+	} while (pudp++, addr = next, addr != end && pud_none(READ_ONCE(*pudp)));
+}
+
+/*
+ * The p4d (fourth level translation table) is unused on ARM32 but we iterate over it to
+ * please the Linux VMM.
+ */
+static void __init kasan_p4d_populate(pgd_t *pgdp, unsigned long addr,
+				      unsigned long end, int node, bool early)
+{
+	unsigned long next;
+	p4d_t *p4dp = p4d_offset(pgdp, addr);
+
+	/* We do not check for p4d_none() as it is unused for sure */
+	if (p4d_none_or_clear_bad(p4dp)) {
+		panic("%s failed to populate p4d for address 0x%lx\n",
+		      __func__, addr);
+		return;
+	}
+
+	do {
+		next = p4d_addr_end(addr, end);
+		kasan_pud_populate(p4dp, addr, next, node, early);
+	} while (p4dp++, addr = next, addr != end);
+}
+
+
+static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
+				      int node, bool early)
+{
+	unsigned long next;
+	pgd_t *pgdp;
+
+	pgdp = pgd_offset_k(addr);
+
+	/* Allocate and populate the PGD if it doesn't already exist */
+	if (!early && pgd_none(*pgdp)) {
+		void *p = kasan_alloc_block(PAGE_SIZE, node);
+
+		if (!p) {
+			panic("%s failed to allocate pgd for address 0x%lx\n",
+			      __func__, addr);
+			return;
+		}
+		pgd_populate(&init_mm, pgdp, p);
+	}
+
+	do {
+		next = pgd_addr_end(addr, end);
+		kasan_p4d_populate(pgdp, addr, next, node, early);
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
+#ifdef CONFIG_ARM_LPAE
+	memcpy(tmp_pmd_table,
+		pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_START)),
+		sizeof(tmp_pmd_table));
+	memcpy(tmp_pgd_table, swapper_pg_dir, sizeof(tmp_pgd_table));
+	set_pgd(&tmp_pgd_table[pgd_index(KASAN_SHADOW_START)],
+		__pgd(__pa(tmp_pmd_table) | PMD_TYPE_TABLE | L_PGD_SWAPPER));
+	cpu_switch_mm(tmp_pgd_table, &init_mm);
+#else
+	memcpy(tmp_pgd_table, swapper_pg_dir, sizeof(tmp_pgd_table));
+	cpu_switch_mm(tmp_pgd_table, &init_mm);
+#endif
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
index c5e1b27046a8..db5ef068e523 100644
--- a/arch/arm/mm/pgd.c
+++ b/arch/arm/mm/pgd.c
@@ -66,7 +66,20 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615090247.5218-5-linus.walleij%40linaro.org.
