Return-Path: <kasan-dev+bncBDLKPY4HVQKBBQPS66AQMGQEQICGWLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A2CD3296F8
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 09:37:22 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id e13sf2851695ejd.21
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 00:37:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614674241; cv=pass;
        d=google.com; s=arc-20160816;
        b=MvxQawexX4Xv1w8ct3xFI093Dg+ATpQcMzYzx2ypK9ikMdm9UMtTMyAPGb0X+Fw8O4
         O7OFN5flRXQmhOZBxXrRRoDO4MR+MmhTDmneCI3lxCcnw5d5HRuB43Lc6qj47RfpCeW2
         qpMJQTP4v58Ob1TKvCk+ympYYrHRjc7zqlAGnUQIITZNJL3ryS9r/reQzsBzZd4r/22o
         LQQhXZ3jf5NGnIMrk7xTsoH+AASJMtDbT2vTIi4+yB0BO2/V4m/7mGmPvkj65nGNVoIT
         7v/o7oNDr9HwTFAneMypsvRoACAoNVF1TiW3ZT1gru/s8NQlae0AwrbHw9YEtf7J6PYo
         IBbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:date:cc:to:subject:from:message-id
         :mime-version:sender:dkim-signature;
        bh=8XvPJfmrF6Fogfwh/st5bofQGH9IXalITm/XkaiSIYg=;
        b=AMp+5TwNX50GGU72lhj7WA/b6m/C23ShevPc54iq4sg8pzem45BUbmmDnIDLKNWjBc
         ncPpo9gUWHrj3t8VjnEeld+DLnXNkdbUJb5dfdIga5zlX42jFnj0gpUFUsK924YVDk4i
         cTrXrl+NjrJWc0O7N1VkngxF3gqBcnkE/pUPgUXONCy/JghFd6q5D3OAicG43I5JRUVv
         +q+Ley4DsuqYjy0+JG/oCd/5mqaFUfSQmZ+7zD3yEQrCBfaq+7/pz1beu+FeFc8l8kHt
         TuZwgcTbIerZg3noW9ULB2WN+5e8lVagIGR7FQhR07kO+u/a+auaY4nHfXTAlNDNySQj
         nktA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:message-id:from:subject:to:cc:date
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8XvPJfmrF6Fogfwh/st5bofQGH9IXalITm/XkaiSIYg=;
        b=gDeb9wyf1dSqced3stp7Y3hwAy7N5l9ZWcsae+f0jg7i2fcdbcmltjmHFnus/tDX4U
         rSEwaciSP/YlsfPaHyrbtvcZu+2kBWpQX70BafnY+Qjpq1DePpT2NG+/TPBydEDcPj8J
         tn/0PmDQbV0GQB7NX9ya/uv7HHocCj0mCYJG0061El/nDpvRpeAWoB+H8qFIhzIfaj0q
         OyHOAQ7Qe+wZ5DFtKa5xM6LfQNHBT7NvhmwmYg389+0EOgFR7lLnEaEZSZz7fDVXbsAs
         Yoj5fM43bakX/E3Uf2h07El260i4qiWuqvX0011DQshE5H6wIYX56MD81tyQWZelvpj0
         /AXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:message-id:from:subject:to
         :cc:date:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8XvPJfmrF6Fogfwh/st5bofQGH9IXalITm/XkaiSIYg=;
        b=DA7Jt2HmBLBerNNwIpk967ukv+eE5jm4qq8xaI0NKUfHuAz4BEIwCz/bEb7c08ZBkR
         ZJTqj0yWgogw0MroCqtsZG0DHniUxyFUCHbSwmGCDY3a+zp9OaPv1oQHL/oKCQ6/mKcU
         1+iMgrEcxjgrzQvojfj6U5DRe4wXpvs5XF0qp7iGfA5fVvPKQfH7DyoeyRiYqPFKmz//
         qBEPMmbMYejVnCTEj1R3NqNBsyi1E6hr2nNcw0uBEEqjgoyV6UbQOKkABPn75uAwMWs+
         YK11awdp5dIHC/L+zN8jp3EUxN870Bf8sNEdHGrb1jjSM7K1nXpR775K+HX973iTFUvJ
         WAaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gYaNiRTVEOHEGZpyF8WW5S3Q/TLsYa99c1OBIesoz+eMe9LIn
	P/btnTraOwFHkrWYQj5TxNE=
X-Google-Smtp-Source: ABdhPJwNk1kertRdzEs8h9aQdFLh0KQQoeRwr6SU8pLqsC5v3duLRfcRr4FjNNMG7Vrkwcutkz8UAw==
X-Received: by 2002:a17:906:3f96:: with SMTP id b22mr19540959ejj.478.1614674241838;
        Tue, 02 Mar 2021 00:37:21 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c909:: with SMTP id b9ls297573edt.2.gmail; Tue, 02 Mar
 2021 00:37:21 -0800 (PST)
X-Received: by 2002:a50:fa42:: with SMTP id c2mr1321132edq.159.1614674240987;
        Tue, 02 Mar 2021 00:37:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614674240; cv=none;
        d=google.com; s=arc-20160816;
        b=CftY4xBxovc0DNHKFbWZ8UJytrI7Dyr7ky+ZHPUMC6X77F09IdTxkyYZXngbbm6S7/
         o32InHJzQF8drndiIacWuRTYjnUJJHAvO99z2lZjwAjLOPDzk71scxpYAbYk8w54WyrS
         B8naB/402UBlaaas2vuzisStiXSTy8Qqb5Ta9dPYGEuQHkAASC5UoZDcH3SZXT0fUELK
         bsVUtJPaoV/Rq6DwHZms3oIwY58qUM89tq3j/zRZF4GT/pHtm9AOzOIvmSahhBdiO0QK
         /7DAH/qh2dqKZv7sEE2mKmJ3Do9wDccq7LbCxeBhNMtuBrRfV7GkupqCbtcQk60u+W2d
         U2uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=date:cc:to:subject:from:message-id;
        bh=qJukquzytiRiBjKtvinoJW+ZcqX+DTNJ8RIxbnzjwJA=;
        b=ebEY9GjKOMWzVF5SRI+WdGB1n540a4t9dXgRr+qJIkGyC1ub2TY31+IzuE05I9TrLd
         l0HAkz/VYrqlRLxTtnl8Qxef0BZNmG1gwMUYkCWqQKXHA9QeFAUBr48fJozKfXWCksbS
         J7Qh72lAi2/ryiRifmiD9C17/K5sn1DttYRDJcg2D+f9PhE/TK35x1F7PJumqMPE7XRf
         jO30q5CX63aNk4NSE1mF8yZEbfzbViLaZa3utmhXNSDLtL3iKKkroprTug2riDBT+uZo
         VUOtYuhPJ34M2xxT/XODHRXwpwAKDV15HekGpicvoTyNRvpLp7mx9J14zKOQxpD+u/WK
         MDhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id df17si406297edb.3.2021.03.02.00.37.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Mar 2021 00:37:20 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4DqVqg2qtDz9ty3b;
	Tue,  2 Mar 2021 09:37:19 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id s4f5dFVf7KEf; Tue,  2 Mar 2021 09:37:19 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4DqVqg1tVqz9ty3Z;
	Tue,  2 Mar 2021 09:37:19 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 4C1428B7AC;
	Tue,  2 Mar 2021 09:37:20 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 1PrP55n13_jm; Tue,  2 Mar 2021 09:37:20 +0100 (CET)
Received: from localhost.localdomain (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id F02628B75F;
	Tue,  2 Mar 2021 09:37:19 +0100 (CET)
Received: by localhost.localdomain (Postfix, from userid 0)
	id B93C3674AD; Tue,  2 Mar 2021 08:37:19 +0000 (UTC)
Message-Id: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Subject: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
Date: Tue,  2 Mar 2021 08:37:19 +0000 (UTC)
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

Unit tests succeed on all tests but one:

	[   15.053324]     # test_invalid_access: EXPECTATION FAILED at mm/kfence/kfence_test.c:636
	[   15.053324]     Expected report_matches(&expect) to be true, but is false
	[   15.068359]     not ok 21 - test_invalid_access

Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
---
 arch/powerpc/Kconfig              | 13 +++++++------
 arch/powerpc/include/asm/kfence.h | 32 +++++++++++++++++++++++++++++++
 arch/powerpc/mm/book3s32/mmu.c    |  2 +-
 arch/powerpc/mm/fault.c           |  7 ++++++-
 arch/powerpc/mm/init_32.c         |  3 +++
 arch/powerpc/mm/nohash/8xx.c      |  5 +++--
 6 files changed, 52 insertions(+), 10 deletions(-)
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
index 000000000000..c229ee6a48f0
--- /dev/null
+++ b/arch/powerpc/include/asm/kfence.h
@@ -0,0 +1,32 @@
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
index d7eb266a3f7a..4548aec95561 100644
--- a/arch/powerpc/mm/book3s32/mmu.c
+++ b/arch/powerpc/mm/book3s32/mmu.c
@@ -162,7 +162,7 @@ unsigned long __init mmu_mapin_ram(unsigned long base, unsigned long top)
 	unsigned long border = (unsigned long)__init_begin - PAGE_OFFSET;
 
 
-	if (debug_pagealloc_enabled() || __map_without_bats) {
+	if (debug_pagealloc_enabled() || __map_without_bats || IS_ENABLED(CONFIG_KFENCE)) {
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
 
diff --git a/arch/powerpc/mm/nohash/8xx.c b/arch/powerpc/mm/nohash/8xx.c
index 19a3eec1d8c5..17051377aed7 100644
--- a/arch/powerpc/mm/nohash/8xx.c
+++ b/arch/powerpc/mm/nohash/8xx.c
@@ -149,7 +149,8 @@ unsigned long __init mmu_mapin_ram(unsigned long base, unsigned long top)
 {
 	unsigned long etext8 = ALIGN(__pa(_etext), SZ_8M);
 	unsigned long sinittext = __pa(_sinittext);
-	bool strict_boundary = strict_kernel_rwx_enabled() || debug_pagealloc_enabled();
+	bool strict_boundary = strict_kernel_rwx_enabled() || debug_pagealloc_enabled() ||
+			       IS_ENABLED(CONFIG_KFENCE);
 	unsigned long boundary = strict_boundary ? sinittext : etext8;
 	unsigned long einittext8 = ALIGN(__pa(_einittext), SZ_8M);
 
@@ -161,7 +162,7 @@ unsigned long __init mmu_mapin_ram(unsigned long base, unsigned long top)
 		return 0;
 
 	mmu_mapin_ram_chunk(0, boundary, PAGE_KERNEL_TEXT, true);
-	if (debug_pagealloc_enabled()) {
+	if (debug_pagealloc_enabled() || IS_ENABLED(CONFIG_KFENCE)) {
 		top = boundary;
 	} else {
 		mmu_mapin_ram_chunk(boundary, einittext8, PAGE_KERNEL_TEXT, true);
-- 
2.25.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy%40csgroup.eu.
