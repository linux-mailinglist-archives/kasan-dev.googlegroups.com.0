Return-Path: <kasan-dev+bncBDE6RCFOWIARBUHI275QKGQERYDK4LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 180AF280286
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 17:22:57 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id l15sf2192359wro.10
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 08:22:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601565777; cv=pass;
        d=google.com; s=arc-20160816;
        b=XeUTRuhL07yvWyIZoX1u3w0roDVnElMVUaLAY7YtNwmvdiA+O+wRXEIr+1Fgw1cJoe
         Fw+FA2VkJRZGps6rXrm52fB+aOvii3SO+zxdDfVIJFR2moum+4sePMMcLFMJUxOJ6IkC
         pRPwx51axMof5Er4fotM0yqMNvDVEWjdhr3dTZMmWQ9szIVDDxk7xV9yg5PAtypGgYLA
         l2U9DUbFwb8XJ5lOUJtjGu9i2iA1TDAo36CDabmMQwfZSF2Q6QjJHhCPVNjDW3vHnWsG
         I9qn4xSxzfZf9G0zTD4Thxn7UcH7vamogd/dQkDXw234LAO70tofpqW7nltZIQ2vpc4r
         Pzug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=T9hgxVXPl18qdQxBFjivGvd2Rr8JO9ZdHM4x0pGYu3c=;
        b=MwlnIII8GgcDS4UyGwmJUa65PPvijEKrD2LgWNhtpjFX0oYBsprzC5//l1U9xAlImI
         CJQ3ZZ0XUQ+mr+gXmn4/GKjrvkwzN5RSoubI2/wQ3yqLmnb41lddwU6MPHeErNM7pLMy
         sqsJDUY7sF8I+N4MNbaeAHyH7qvbGwWOXwy3OBMT9N11A4Ws52zbP8Wi34UYiOyps9fK
         MAENrHmy/ZMJnp4Q+yqi3pmK5YgfDRkqGwhul25ZuIpZxMNeN6yxuZ8el4Okkw4ffyze
         625RgaT80aNjIcz8fYr7yIUyzETudMg/AS0jgRTcqRj7Z/QpcXeH0KPjApHCoj/B8uim
         FISg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=wjnrPJ7I;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T9hgxVXPl18qdQxBFjivGvd2Rr8JO9ZdHM4x0pGYu3c=;
        b=kuCOCKYnif0Oz4w4dRlxRuwzSSmE3qdOonh4mvvdwwxeOXOZcJYx4ZUFnAnkRTANqx
         ewXIJW141phXEW1gj9/tJuj6pO4/uaV13uqBo+ljWCUHoCldjGh3CmYDRBkIwoPlcBtC
         tPuMCCyBMoOFfi0TtDrnsLeQNe6ZWQabOrvWHlrIrbqy2fst1aElU4+5r4tMOSfFjFVt
         8HhYwd9V7R5wwhh+Qn+KY7DeHxtNIr2vKgT50lXvRxa+99io7nmlBgpmrK1k+JOOVdHR
         eAYkvQ32Me4jvRxxG5IXgZ3Sjd/GdKZW+G757tCMLWb8XBCt1M3R6/U32C0sgFE5uUic
         yFWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T9hgxVXPl18qdQxBFjivGvd2Rr8JO9ZdHM4x0pGYu3c=;
        b=WNUEfwZiUVBhpqRfgEeqDsN1NkVdhfXcRqnvm+6uO0c0Fq2q/oCuWKjfpNSpz7/98k
         AQXRad0fxtREFWmZQnmihYaQw+ARg4n3VDm+YdQ/sJBKdFI7qmdBQG6dtXzmDioVavTh
         m2J8trnrOEs3BL+aau/yZVRSKIgT65O6WunfwpTOQRYfN3ylie152dH3/JFzf5VBCsDh
         IxrwGasHDSVvi/UrILdDINsodVQBIUbjS7fmySC6XfJi0C0cDD5+mIsLNZmP4bCmZeqb
         09JbyVc+a4uK83hd7GyFhVk7+XUHYZ/eeQTbWOTpEdwfUlo0Sa39MWKW6KulB9cwiKgh
         U3VA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530twqHiQjGPsXWhNF8LUv4WGneR35ZPZH5Q4wa/g5YY+FBK60W+
	gLXL/U/CPXgw0eBMBBSpRDc=
X-Google-Smtp-Source: ABdhPJw5Q3Ifcg69V2BHfRyF0/YZn7unW0jWB5JdOIwqZjMINSntBgY6PCC83zX6nNcbHCacmiYy6Q==
X-Received: by 2002:adf:f548:: with SMTP id j8mr10023257wrp.114.1601565776779;
        Thu, 01 Oct 2020 08:22:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9986:: with SMTP id b128ls3091819wme.3.canary-gmail;
 Thu, 01 Oct 2020 08:22:55 -0700 (PDT)
X-Received: by 2002:a1c:4683:: with SMTP id t125mr573060wma.110.1601565775899;
        Thu, 01 Oct 2020 08:22:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601565775; cv=none;
        d=google.com; s=arc-20160816;
        b=KfaHm4/y2ST4c7B7jSuI6EgfKVr6HgB1FMOLJgVVsQMOtwQdVeLr9cGJI/d9amdmSt
         FZgoeZ0/biqiBRGl+hakTDj8M0N/JGIAkEpAhrfzln3Qp2khOTiFXXmxrqliDIHbqlMo
         dOBKXvbaHok+BH/57VCPjxl92LePhvU5UuIY5a1ggn0bmqjTC7ZQWKfkatf+DrSEk5gG
         C0mgKzFFEA9ZgMQ178r5G1SnsdmrPDKYhqvS5CaMQhCAALgV8KUKcjMkGEdHWyZ18eNe
         pf8x7/FFUKhh8r7NA8ceMQp0+ccw8/sE2aahINbBGhuCB8MSnBdgtGa16dGhsJGVg+d8
         scyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6c2oZQgEOq3qaJBrP8nAyg7M5eQEASzXeNUeW+aRyRM=;
        b=zDzD0AeJ8GN/NQ0OxenDFG2Ab/7eCNFdq6nhO59lm28fARvBePaVDG0JVbK6OzXgq+
         6m5cSiBnRR9F1wqFdq3sYtKDpL0A2T8WzjbDiknFxcZtBkZxSgLonCdxbzB4QGfjl0QP
         Nvr+igqPXf+UzLem8xz+KE1slZ/wRh27dOemDObDFGQ/tSE7/eHOUEJwTzP4pg/gRDun
         YFhuEwCSwwR/G/x6hBufrNCoo16FsGM9VXh7laR6tb1Za/JYN02cznnahHQHD7rLRC++
         LyQTHnzkZheg+xSIp5E5seL1k9AmkZAPqlyMH9tl856MUs9GvIpwBhaaERe4zN7CPBBe
         ipRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=wjnrPJ7I;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x142.google.com (mail-lf1-x142.google.com. [2a00:1450:4864:20::142])
        by gmr-mx.google.com with ESMTPS id z17si147713wrm.2.2020.10.01.08.22.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 08:22:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) client-ip=2a00:1450:4864:20::142;
Received: by mail-lf1-x142.google.com with SMTP id z19so7085502lfr.4
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 08:22:55 -0700 (PDT)
X-Received: by 2002:a19:5e5d:: with SMTP id z29mr2683992lfi.32.1601565775111;
        Thu, 01 Oct 2020 08:22:55 -0700 (PDT)
Received: from genomnajs.ideon.se ([85.235.10.227])
        by smtp.gmail.com with ESMTPSA id v18sm587578lfa.238.2020.10.01.08.22.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 08:22:54 -0700 (PDT)
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
Subject: [PATCH 5/6 v14] ARM: Initialize the mapping of KASan shadow memory
Date: Thu,  1 Oct 2020 17:22:31 +0200
Message-Id: <20201001152232.274367-6-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20201001152232.274367-1-linus.walleij@linaro.org>
References: <20201001152232.274367-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=wjnrPJ7I;       spf=pass
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
Co-developed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Co-developed-by: Abbott Liu <liuwenliang@huawei.com>
Co-developed-by: Ard Biesheuvel <ardb@kernel.org>
Acked-by: Mike Rapoport <rppt@linux.ibm.com>
Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
Reported-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v13->v14:
- Provide more elaborate prints of how virtual kernel memory
  is mapped to the allocated lowmem pages.
- Make sure to also map the memory around the __atags_pointer:
  this memory is used for the device tree blob (DTB) and will be
  accessed by the device tree parser. We were just lucky that
  this was mostly in some acceptable memory location until now.
ChangeLog v12->v13:
- Rebase on kernel v5.9-rc1
ChangeLog v11->v12:
- Do not try to shadow highmem memory blocks. (Ard)
- Provoke a build bug if the entire shadow memory doesn't fit
  inside a single pgd_index() (Ard)
- Move the pointer to (unsigned long) casts into the create_mapping()
  function. (Ard)
- After setting up the shadow memory make sure to issue
  local_flush_tlb_all() so that we refresh all the global mappings. (Ard)
- Simplify pte_populate() (Ard)
- Skip over pud population as well as p4d. (Ard)
- Drop the stop condition pmd_none(*pmdp) in the pmd population
  loop. (Ard)
- Stop passing around the node (NUMA) parameter in the init code,
  we are not expecting any NUMA architectures to be introduced into
  ARM32 so just hardcode NUMA_NO_NODE when calling
  memblock_alloc_try_nid().
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
 arch/arm/mm/kasan_init.c           | 286 +++++++++++++++++++++++++++++
 arch/arm/mm/pgd.c                  |  16 +-
 8 files changed, 356 insertions(+), 2 deletions(-)
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
index 15f4674715f8..fdee1f04f4f3 100644
--- a/arch/arm/include/asm/pgalloc.h
+++ b/arch/arm/include/asm/pgalloc.h
@@ -21,6 +21,7 @@
 #define _PAGE_KERNEL_TABLE	(PMD_TYPE_TABLE | PMD_BIT4 | PMD_DOMAIN(DOMAIN_KERNEL))
 
 #ifdef CONFIG_ARM_LPAE
+#define PGD_SIZE		(PTRS_PER_PGD * sizeof(pgd_t))
 
 static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
 {
@@ -28,14 +29,19 @@ static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
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
index 536b6b979f63..56fae7861fd3 100644
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
index d0562cdc919e..8b28eca23326 100644
--- a/arch/arm/kernel/setup.c
+++ b/arch/arm/kernel/setup.c
@@ -58,6 +58,7 @@
 #include <asm/unwind.h>
 #include <asm/memblock.h>
 #include <asm/virt.h>
+#include <asm/kasan.h>
 
 #include "atags.h"
 
@@ -1132,6 +1133,7 @@ void __init setup_arch(char **cmdline_p)
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
index 000000000000..6fd9bc70970f
--- /dev/null
+++ b/arch/arm/mm/kasan_init.c
@@ -0,0 +1,286 @@
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
+extern unsigned long __atags_pointer;
+
+static __init void *kasan_alloc_block(size_t size)
+{
+	return memblock_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
+				      MEMBLOCK_ALLOC_KASAN, NUMA_NO_NODE);
+}
+
+static void __init kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
+				      unsigned long end, bool early)
+{
+	unsigned long next;
+	pte_t *ptep = pte_offset_kernel(pmdp, addr);
+
+	do {
+		pte_t entry;
+
+		next = addr + PAGE_SIZE;
+
+		if (!early) {
+			void *p = kasan_alloc_block(PAGE_SIZE);
+			if (!p) {
+				panic("%s failed to alloc pte for address 0x%lx\n",
+				      __func__, addr);
+				return;
+			}
+			memset(p, KASAN_SHADOW_INIT, PAGE_SIZE);
+			entry = pfn_pte(virt_to_pfn(p),
+					__pgprot(pgprot_val(PAGE_KERNEL)));
+		} else if (pte_none(READ_ONCE(*ptep))) {
+			/*
+			 * The early shadow memory is mapping all KASan
+			 * operations to one and the same page in memory,
+			 * "kasan_early_shadow_page" so that the instrumentation
+			 * will work on a scratch area until we can set up the
+			 * proper KASan shadow memory.
+			 */
+			entry = pfn_pte(virt_to_pfn(kasan_early_shadow_page),
+					__pgprot(_L_PTE_DEFAULT | L_PTE_DIRTY | L_PTE_XN));
+		} else {
+			/*
+			 * Early shadow mappings are PMD_SIZE aligned, so if the
+			 * first entry is already set, they must all be set.
+			 */
+			return;
+		}
+
+		set_pte_at(&init_mm, addr, ptep, entry);
+	} while (ptep++, addr = next, addr != end);
+}
+
+/*
+ * The pmd (page middle directory) is only used on LPAE
+ */
+static void __init kasan_pmd_populate(pud_t *pudp, unsigned long addr,
+				      unsigned long end, bool early)
+{
+	unsigned long next;
+	pmd_t *pmdp = pmd_offset(pudp, addr);
+
+	do {
+		if (pmd_none(*pmdp)) {
+			void *p = early ? kasan_early_shadow_pte :
+				kasan_alloc_block(PAGE_SIZE);
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
+		kasan_pte_populate(pmdp, addr, next, early);
+	} while (pmdp++, addr = next, addr != end);
+}
+
+static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
+				      bool early)
+{
+	unsigned long next;
+	pgd_t *pgdp;
+	p4d_t *p4dp;
+	pud_t *pudp;
+
+	pgdp = pgd_offset_k(addr);
+
+	do {
+		/* Allocate and populate the PGD if it doesn't already exist */
+		if (!early && pgd_none(*pgdp)) {
+			void *p = kasan_alloc_block(PAGE_SIZE);
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
+		 * We just immediately jump over the p4d and pud page
+		 * directories since we believe ARM32 will never gain four
+		 * nor five level page tables.
+		 */
+		p4dp = p4d_offset(pgdp, addr);
+		pudp = pud_offset(p4dp, addr);
+
+		kasan_pmd_populate(pudp, addr, next, early);
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
+	kasan_pgd_populate(KASAN_SHADOW_START, KASAN_SHADOW_END, true);
+}
+
+static void __init clear_pgds(unsigned long start,
+			unsigned long end)
+{
+	for (; start && start < end; start += PMD_SIZE)
+		pmd_clear(pmd_off_k(start));
+}
+
+static int __init create_mapping(void *start, void *end)
+{
+	void *shadow_start, *shadow_end;
+
+	shadow_start = kasan_mem_to_shadow(start);
+	shadow_end = kasan_mem_to_shadow(end);
+
+	pr_info("Mapping kernel virtual memory block: %px-%px at shadow: %px-%px\n",
+		start, end, shadow_start, shadow_end);
+
+	kasan_pgd_populate((unsigned long)shadow_start & PAGE_MASK,
+			   (unsigned long)shadow_end, false);
+	return 0;
+}
+
+void __init kasan_init(void)
+{
+	struct memblock_region *reg;
+	unsigned long atags;
+	int i;
+
+	/*
+	 * We are going to perform proper setup of shadow memory.
+	 *
+	 * At first we should unmap early shadow (clear_pgds() call bellow).
+	 * However, instrumented code can't execute without shadow memory.
+	 *
+	 * To keep the early shadow memory MMU tables around while setting up
+	 * the proper shadow memory, we copy swapper_pg_dir (the initial page
+	 * table) to tmp_pgd_table and use that to keep the early shadow memory
+	 * mapped until the full shadow setup is finished. Then we swap back
+	 * to the proper swapper_pg_dir.
+	 */
+
+	memcpy(tmp_pgd_table, swapper_pg_dir, sizeof(tmp_pgd_table));
+#ifdef CONFIG_ARM_LPAE
+	/* We need to be in the same PGD or this won't work */
+	BUILD_BUG_ON(pgd_index(KASAN_SHADOW_START) !=
+		     pgd_index(KASAN_SHADOW_END));
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
+		/* Do not attempt to shadow highmem */
+		if (reg->base >= arm_lowmem_limit) {
+			pr_info("Skip highmem block %px-%px\n",
+				start, end);
+			continue;
+		}
+		if (reg->base + reg->size > arm_lowmem_limit) {
+			pr_info("Truncate memory block %px-%px\n to %px-%px\n",
+				start, end, start, __va(arm_lowmem_limit));
+			end = __va(arm_lowmem_limit);
+		}
+		if (start >= end) {
+			pr_info("Skipping invalid memory block %px-%px\n",
+				start, end);
+			continue;
+		}
+
+		create_mapping(start, end);
+	}
+
+	/*
+	 * 1. The module global variables are in MODULES_VADDR ~ MODULES_END,
+	 *    so we need to map this area.
+	 * 2. PKMAP_BASE ~ PKMAP_BASE+PMD_SIZE's shadow and MODULES_VADDR
+	 *    ~ MODULES_END's shadow is in the same PMD_SIZE, so we can't
+	 *    use kasan_populate_zero_shadow.
+	 */
+	create_mapping((void *)MODULES_VADDR, (void *)(PKMAP_BASE + PMD_SIZE));
+
+	/* Populate the data area around the ATAGs pointer (also used for DTB) */
+	atags = __atags_pointer;
+	atags &= PMD_MASK;
+	create_mapping((void *)phys_to_virt(atags),
+		       (void *)phys_to_virt(atags + PMD_SIZE));
+
+	/*
+	 * KAsan may reuse the contents of kasan_early_shadow_pte directly, so
+	 * we should make sure that it maps the zero page read-only.
+	 */
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		set_pte_at(&init_mm, KASAN_SHADOW_START + i*PAGE_SIZE,
+			   &kasan_early_shadow_pte[i],
+			   pfn_pte(virt_to_pfn(kasan_early_shadow_page),
+				__pgprot(pgprot_val(PAGE_KERNEL)
+					 | L_PTE_RDONLY)));
+	local_flush_tlb_all();
+
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
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001152232.274367-6-linus.walleij%40linaro.org.
