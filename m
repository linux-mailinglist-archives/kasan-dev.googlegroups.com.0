Return-Path: <kasan-dev+bncBDLKPY4HVQKBBH7AQOBAMGQE7KGFYHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 626EC32D559
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 15:35:12 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id h30sf14502902wrh.10
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 06:35:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614868512; cv=pass;
        d=google.com; s=arc-20160816;
        b=hovWLn5KifLqLupSqZXezeiP5LMKLbSxl2OxomSfkECn7z3boOCVJlWdk0ng8XvhYv
         IBVBIn0EhyRRfn69C8qvfGveZJnCSc5svXQShAdvUnmHy3us72WpmVKlowooAr+Nw7Ir
         Taw9Me2sqblDz9KhbrzPIcwwWdNgc1ESnoPE/3IVWBbjTjOuNmU/D/be6offgsnw9ENA
         8chlb63G5AsDot5MiNw8E6TEXUkwN1iGzY7VmwBRq9qwenb9AGphfSDoUro0fGpKegX/
         rBgQ6tIrYf02tTiHR+SB7yXpCRggmebnj12um1ojayQ1fOsDZToExcl8TQQkmn5ZHQ1f
         HDDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:date:cc:to:subject:from:message-id
         :mime-version:sender:dkim-signature;
        bh=S0Br6AQN/u7BJe/Bo1hhFyttNYlS6C+gQhcCPAx+CiI=;
        b=tO0wBXdAYQNgbL+xyE4BjwqAhrXPfNAgDu/jwVIHsg46izF6qQNU92kT6Ys4WT8TvH
         G29nn9Lt9++YKOIqir9fRvt7vKvl93ts8wIcjOabKVYYOSgzmQ25GaR2yf8E5UlaPzEA
         hokdEWTXjtoJaupOilbeL+HOFWnwVP/YBWdyaPDZDs9JjrVOm+yoLQI1pzHeRs/QnsyJ
         qxtYT2R0Ye+LIvXYmR22Tt1oZPeEZfl+sHsj00OpYYLKq23e1APPiC/eM1J2tKT/C/FI
         gwiFwfz5+igNcVMlVsjKgcZXmiZd3SHFg9+LFdYfFrIXxK916jGKBjtbzXQAtRextOyC
         R6EA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:message-id:from:subject:to:cc:date
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S0Br6AQN/u7BJe/Bo1hhFyttNYlS6C+gQhcCPAx+CiI=;
        b=mAyvT5Gt2EkXaKOGAR4qYhBo1Kc8NgYXAmnl0bCBeqHGcoc+L9GsKVFiK7q5JElZqb
         fEAldbEBX7zYaavV6bISjv/h2MJhIrGjyb+WKI6OHw+vvAOAzKuOINufB8uzpPOR0mfq
         WIR3pbCjEXTUFwEiPQLLpgPkSJeCiV733T1qao/E5wJPDaLx8IhjEmuUkAg/IJFacnva
         skTUc4dBa32BSakzxqJk11Pe1QIwvk68WCvNCLVLDlo0EhhKtXIAdFDWtlQqHxBkUU9h
         hCDLGFm6qJyoKH5H8OFHhhXk0NgAw2D3LiFPsON2mflutBM4LuttKZsoXaEa6/lh2YxZ
         SYgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:message-id:from:subject:to
         :cc:date:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S0Br6AQN/u7BJe/Bo1hhFyttNYlS6C+gQhcCPAx+CiI=;
        b=o8Ce8CwCJmbUSQOzeR7ncPyjoGSzizEDycPG5yNLRvxNiKqQZIC17BqcWxQTGw1PNn
         DWecBMGKPNwISNmQvxt3SIvwNfZe2sW+BwjDQX0IGi17nEvtJhPQYWHlOTZR74LBiURY
         8aHhRULn1qdYt9MdY2LPbbVwwki6L5Zkr/2rWGyINoORZ18Rd+DGjvWPlLVIVi5c0vTB
         Y4Iq76/JJsCmLbihupX02pxWpeVP55gXvvs9cvKNqkTTCZOnNPN8N/4UWqhWFrFM2zLT
         TFKlIAXjD3qeJMvf/2FMXcoa6MgPTEAVjjtuOT/HHJ3zrUYP3EhLRxQVqkREutPY2MZq
         9gyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Vth+wDnX7Rdm6Gct4OX8wIiHrBKgiogzERrXmYEhxgpOmnHx+
	6rcWCH4oBmymHoJ72HjeVUA=
X-Google-Smtp-Source: ABdhPJy+V/R0graSNqIvpEf2TLh18s8mi/qxyTUP1rha/X2g7+aG1hJQTtGnHDTVkcn/3ZHayVMV1w==
X-Received: by 2002:a5d:58e8:: with SMTP id f8mr4463327wrd.102.1614868512118;
        Thu, 04 Mar 2021 06:35:12 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4ecf:: with SMTP id s15ls3740390wrv.1.gmail; Thu, 04 Mar
 2021 06:35:11 -0800 (PST)
X-Received: by 2002:adf:e412:: with SMTP id g18mr4456138wrm.159.1614868511274;
        Thu, 04 Mar 2021 06:35:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614868511; cv=none;
        d=google.com; s=arc-20160816;
        b=VzVLAYohj5g5gD9CxQTBouxPulL0JTCWQppikTrWhe9G8X6oNkePWBEa/N8hQjHu2z
         pIyKEcMltm3g8H26JxqaEQ2/1cUz/N7WAEVQenImA1xTSx6H44F7PHb+crvXgIFQWiPd
         Fae7gkhrk/0Q+SF80mWYesnG0uv51GQtAETQXAEq5qLbs24iUdrxR+4oOLscOXjPkZNX
         +HBhtNZx6L7Lmh7oZWD9YaqhWLEAvuKKbthxb03z7n9lpJMoByv932G+6Yy3paJXGaUl
         W/AH63EMOTxOMAjZYPclKY2XRHk1YdHn7UgCwa2TsVim/0s9dN5euCXLV0YU2rLOlbAU
         p22g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=date:cc:to:subject:from:message-id;
        bh=jFIK42yv5DVx/fVSQIsa8zxJL3SKbkD+aC6JfgvH+XM=;
        b=ev2ftOCC3rUxt4cpylV6URRf9Zr7KqcshtZx3YZSumu7humFokQldFh7ZOr/ISI48c
         PYzZOzA26iMPUfkYFAckGVfY5EcH//UJNanENq/vmFXnl67gyJtrZOsG0obWy89s2HwC
         xYYCXJy+2WrRrRjabnQ+Im/ytPuUmQI9/+EJk60C+kmEKGWMqzwtXAJw8EdnV10Mzgms
         USFHeSn8HepyDnGpPueHY2sZi6qOnYo621gwoPsinYDf0sRDMUuXss/zBfQdkS0uaQZ7
         n07E7f4ytyYkl6RLToiCJO5J/Fix0i8ZTEWa/vpPhQFUv8gPSTCTqEC3AUoa5Qcmx4Er
         HujQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id i22si587351wml.2.2021.03.04.06.35.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Mar 2021 06:35:11 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Drtgc62BzzB09ZS;
	Thu,  4 Mar 2021 15:35:08 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id DTtRosK72nom; Thu,  4 Mar 2021 15:35:08 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Drtgc4xSwzB09ZR;
	Thu,  4 Mar 2021 15:35:08 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id BA4FE8B812;
	Thu,  4 Mar 2021 15:35:10 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id ySp8nygo6T9K; Thu,  4 Mar 2021 15:35:10 +0100 (CET)
Received: from po16121vm.idsi0.si.c-s.fr (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 46FBF8B80A;
	Thu,  4 Mar 2021 15:35:10 +0100 (CET)
Received: by po16121vm.idsi0.si.c-s.fr (Postfix, from userid 0)
	id 09FDF674E6; Thu,  4 Mar 2021 14:35:09 +0000 (UTC)
Message-Id: <8dfe1bd2abde26337c1d8c1ad0acfcc82185e0d5.1614868445.git.christophe.leroy@csgroup.eu>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Subject: [PATCH v2 1/4] powerpc: Enable KFENCE for PPC32
To: Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
Date: Thu,  4 Mar 2021 14:35:09 +0000 (UTC)
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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

Add architecture specific implementation details for KFENCE and enable
KFENCE for the ppc32 architecture. In particular, this implements the
required interface in <asm/kfence.h>.

KFENCE requires that attributes for pages from its memory pool can
individually be set. Therefore, force the Read/Write linear map to be
mapped at page granularity.

Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Acked-by: Marco Elver <elver@google.com>
---
v2: Added debug_pagealloc_enabled_or_kfence()
---
 arch/powerpc/Kconfig              | 13 ++++++------
 arch/powerpc/include/asm/kfence.h | 33 +++++++++++++++++++++++++++++++
 arch/powerpc/mm/book3s32/mmu.c    |  2 +-
 arch/powerpc/mm/fault.c           |  7 ++++++-
 arch/powerpc/mm/init_32.c         |  3 +++
 arch/powerpc/mm/mmu_decl.h        |  5 +++++
 arch/powerpc/mm/nohash/8xx.c      |  4 ++--
 7 files changed, 57 insertions(+), 10 deletions(-)
 create mode 100644 arch/powerpc/include/asm/kfence.h

diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index 386ae12d8523..d46db0bfb998 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -185,6 +185,7 @@ config PPC
 	select HAVE_ARCH_KASAN			if PPC32 && PPC_PAGE_SHIFT <= 14
 	select HAVE_ARCH_KASAN_VMALLOC		if PPC32 && PPC_PAGE_SHIFT <= 14
 	select HAVE_ARCH_KGDB
+	select HAVE_ARCH_KFENCE			if PPC32
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT
 	select HAVE_ARCH_NVRAM_OPS
@@ -786,7 +787,7 @@ config THREAD_SHIFT
 config DATA_SHIFT_BOOL
 	bool "Set custom data alignment"
 	depends on ADVANCED_OPTIONS
-	depends on STRICT_KERNEL_RWX || DEBUG_PAGEALLOC
+	depends on STRICT_KERNEL_RWX || DEBUG_PAGEALLOC || KFENCE
 	depends on PPC_BOOK3S_32 || (PPC_8xx && !PIN_TLB_DATA && !STRICT_KERNEL_RWX)
 	help
 	  This option allows you to set the kernel data alignment. When
@@ -798,13 +799,13 @@ config DATA_SHIFT_BOOL
 config DATA_SHIFT
 	int "Data shift" if DATA_SHIFT_BOOL
 	default 24 if STRICT_KERNEL_RWX && PPC64
-	range 17 28 if (STRICT_KERNEL_RWX || DEBUG_PAGEALLOC) && PPC_BOOK3S_32
-	range 19 23 if (STRICT_KERNEL_RWX || DEBUG_PAGEALLOC) && PPC_8xx
+	range 17 28 if (STRICT_KERNEL_RWX || DEBUG_PAGEALLOC || KFENCE) && PPC_BOOK3S_32
+	range 19 23 if (STRICT_KERNEL_RWX || DEBUG_PAGEALLOC || KFENCE) && PPC_8xx
 	default 22 if STRICT_KERNEL_RWX && PPC_BOOK3S_32
-	default 18 if DEBUG_PAGEALLOC && PPC_BOOK3S_32
+	default 18 if (DEBUG_PAGEALLOC || KFENCE) && PPC_BOOK3S_32
 	default 23 if STRICT_KERNEL_RWX && PPC_8xx
-	default 23 if DEBUG_PAGEALLOC && PPC_8xx && PIN_TLB_DATA
-	default 19 if DEBUG_PAGEALLOC && PPC_8xx
+	default 23 if (DEBUG_PAGEALLOC || KFENCE) && PPC_8xx && PIN_TLB_DATA
+	default 19 if (DEBUG_PAGEALLOC || KFENCE) && PPC_8xx
 	default PPC_PAGE_SHIFT
 	help
 	  On Book3S 32 (603+), DBATs are used to map kernel text and rodata RO.
diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/asm/kfence.h
new file mode 100644
index 000000000000..a9846b68c6b9
--- /dev/null
+++ b/arch/powerpc/include/asm/kfence.h
@@ -0,0 +1,33 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * powerpc KFENCE support.
+ *
+ * Copyright (C) 2020 CS GROUP France
+ */
+
+#ifndef __ASM_POWERPC_KFENCE_H
+#define __ASM_POWERPC_KFENCE_H
+
+#include <linux/mm.h>
+#include <asm/pgtable.h>
+
+static inline bool arch_kfence_init_pool(void)
+{
+	return true;
+}
+
+static inline bool kfence_protect_page(unsigned long addr, bool protect)
+{
+	pte_t *kpte = virt_to_kpte(addr);
+
+	if (protect) {
+		pte_update(&init_mm, addr, kpte, _PAGE_PRESENT, 0, 0);
+		flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
+	} else {
+		pte_update(&init_mm, addr, kpte, 0, _PAGE_PRESENT, 0);
+	}
+
+	return true;
+}
+
+#endif /* __ASM_POWERPC_KFENCE_H */
diff --git a/arch/powerpc/mm/book3s32/mmu.c b/arch/powerpc/mm/book3s32/mmu.c
index d7eb266a3f7a..a0db398b5c26 100644
--- a/arch/powerpc/mm/book3s32/mmu.c
+++ b/arch/powerpc/mm/book3s32/mmu.c
@@ -162,7 +162,7 @@ unsigned long __init mmu_mapin_ram(unsigned long base, unsigned long top)
 	unsigned long border = (unsigned long)__init_begin - PAGE_OFFSET;
 
 
-	if (debug_pagealloc_enabled() || __map_without_bats) {
+	if (debug_pagealloc_enabled_or_kfence() || __map_without_bats) {
 		pr_debug_once("Read-Write memory mapped without BATs\n");
 		if (base >= border)
 			return base;
diff --git a/arch/powerpc/mm/fault.c b/arch/powerpc/mm/fault.c
index bb368257b55c..bea13682c909 100644
--- a/arch/powerpc/mm/fault.c
+++ b/arch/powerpc/mm/fault.c
@@ -32,6 +32,7 @@
 #include <linux/context_tracking.h>
 #include <linux/hugetlb.h>
 #include <linux/uaccess.h>
+#include <linux/kfence.h>
 
 #include <asm/firmware.h>
 #include <asm/interrupt.h>
@@ -418,8 +419,12 @@ static int ___do_page_fault(struct pt_regs *regs, unsigned long address,
 	 * take a page fault to a kernel address or a page fault to a user
 	 * address outside of dedicated places
 	 */
-	if (unlikely(!is_user && bad_kernel_fault(regs, error_code, address, is_write)))
+	if (unlikely(!is_user && bad_kernel_fault(regs, error_code, address, is_write))) {
+		if (kfence_handle_page_fault(address, is_write, regs))
+			return 0;
+
 		return SIGSEGV;
+	}
 
 	/*
 	 * If we're in an interrupt, have no user context or are running
diff --git a/arch/powerpc/mm/init_32.c b/arch/powerpc/mm/init_32.c
index 02c7db4087cb..3d690be48e84 100644
--- a/arch/powerpc/mm/init_32.c
+++ b/arch/powerpc/mm/init_32.c
@@ -97,6 +97,9 @@ static void __init MMU_setup(void)
 	if (IS_ENABLED(CONFIG_PPC_8xx))
 		return;
 
+	if (IS_ENABLED(CONFIG_KFENCE))
+		__map_without_ltlbs = 1;
+
 	if (debug_pagealloc_enabled())
 		__map_without_ltlbs = 1;
 
diff --git a/arch/powerpc/mm/mmu_decl.h b/arch/powerpc/mm/mmu_decl.h
index 998810e68562..7dac910c0b21 100644
--- a/arch/powerpc/mm/mmu_decl.h
+++ b/arch/powerpc/mm/mmu_decl.h
@@ -185,3 +185,8 @@ void ptdump_check_wx(void);
 #else
 static inline void ptdump_check_wx(void) { }
 #endif
+
+static inline bool debug_pagealloc_enabled_or_kfence(void)
+{
+	return IS_ENABLED(CONFIG_KFENCE) || debug_pagealloc_enabled();
+}
diff --git a/arch/powerpc/mm/nohash/8xx.c b/arch/powerpc/mm/nohash/8xx.c
index 19a3eec1d8c5..71bfdbedacee 100644
--- a/arch/powerpc/mm/nohash/8xx.c
+++ b/arch/powerpc/mm/nohash/8xx.c
@@ -149,7 +149,7 @@ unsigned long __init mmu_mapin_ram(unsigned long base, unsigned long top)
 {
 	unsigned long etext8 = ALIGN(__pa(_etext), SZ_8M);
 	unsigned long sinittext = __pa(_sinittext);
-	bool strict_boundary = strict_kernel_rwx_enabled() || debug_pagealloc_enabled();
+	bool strict_boundary = strict_kernel_rwx_enabled() || debug_pagealloc_enabled_or_kfence();
 	unsigned long boundary = strict_boundary ? sinittext : etext8;
 	unsigned long einittext8 = ALIGN(__pa(_einittext), SZ_8M);
 
@@ -161,7 +161,7 @@ unsigned long __init mmu_mapin_ram(unsigned long base, unsigned long top)
 		return 0;
 
 	mmu_mapin_ram_chunk(0, boundary, PAGE_KERNEL_TEXT, true);
-	if (debug_pagealloc_enabled()) {
+	if (debug_pagealloc_enabled_or_kfence()) {
 		top = boundary;
 	} else {
 		mmu_mapin_ram_chunk(boundary, einittext8, PAGE_KERNEL_TEXT, true);
-- 
2.25.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8dfe1bd2abde26337c1d8c1ad0acfcc82185e0d5.1614868445.git.christophe.leroy%40csgroup.eu.
