Return-Path: <kasan-dev+bncBAABB5HJUGTAMGQEU5CXHQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 92AF176A741
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Aug 2023 04:59:02 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2684179be07sf3264304a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 19:59:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690858741; cv=pass;
        d=google.com; s=arc-20160816;
        b=zWW2YkSNAJVBX/bvaS0eN8VB1byddSZOJdscw7FYwG7qSpH8LKSMmSnVxYaLpVYG10
         Z/p/eo87hjzjTF4vOuoccN1nNcnqr5ZaaHYMG9NabVBqfNIVkEW49DNwMMiuzAv3+lAs
         0qlSe74mKwRrxMZ/TnF6hEeBMtR2orTFmtzcH0Zv/s6WklQj4zVf+Bo8OpmIbXjwIFGT
         IvwmwoX9N/NiJJNJiBqUiKF9AecG6dXKTMYssuYyM3M/ztXs++LexeC5CjyVdXJLROE9
         MUDyjLTQE5Hz5H9FMYJuFv1gtPajvXM2SQchy/MpmX4/mPR41WeEqdJFaCAVe3ipTXpg
         tm6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9nLpzihhG3l8Npl7KuBssEe4bvODgDBNwgXvBAs8zjU=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=vsreuXRxgb/9kbh0ohaKDfK/HijTGA6jIWZ5h+5G0GN7QnqQw7S5sclZdbE59HGkLn
         irI8DXsXpRBVrHpAUhxqfrmGUWwqNakNDogEbEQ/fviJnw9Jw4waDip6CD46WgkoZ5GB
         8uKrkFaF+8J6Tf+i+Zx3gK+EXbALpOfWC0yPhrseoxqcwtN8lTCsSvsLsAz0sLivkBAv
         +iTElBJkw/ZrhUE0bLMSJ/+TFSq6ktj1REwY9bZ3TgEgRVsi1ro3i7fJfdXhyw0OUXaV
         ibPqJbZYUlMimS0huD6XPuryb9fpZE3DjFYCH3dOBTz3iTpFQ+xY2AfYzndaBH7a+8mG
         sSZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690858741; x=1691463541;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9nLpzihhG3l8Npl7KuBssEe4bvODgDBNwgXvBAs8zjU=;
        b=PyrQDSkaLw8V0W1Gb9spFI3Oh3oAKxO6YQtzqUVRbLceM4FOfB/rtPxAF96uZK9xqZ
         Q91eQxhxBl6TMqeBPC4tYFzC2kxLfgyIrMmE5nRq9+frqPT6x1ooUtldEagMlpD4lw+h
         YDvNEYXPQD4IIm/MaIy2bi7HXBoQLfTpQlFEw6pv+sZtIK0ry4eD9soqUuXj3qptvKiX
         l+49AnJMClPeElzdkOquq03bjiGamIZO/M47Uinw08tQt11yzoZZagFT7LO5rEDJinuu
         RVaFX33RF4lvsXgbKuMktvJE+TKu7XnegEY4+Xnv9ohEKZPea0dbcyvhE8oRH8/HGpuV
         WD7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690858741; x=1691463541;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9nLpzihhG3l8Npl7KuBssEe4bvODgDBNwgXvBAs8zjU=;
        b=hwQsvE1a2oRofig+aE2KmnPfx2u8v4qoEAgEiUNptso5Iv9Sy9Xs+PWYsbkZgbUorz
         suEs2XS3yEMkfbbMUwmZWEQWZSljkst1+45bSsmbLEh2dGOpHRpkaQ1ET6VvLREwFBOg
         DrqG4ojndzUyQ7e1+gpxUa5xhxZJ3lSGMEr/WONC0C0nWSIcqzrnT0XEVpGy3ADxYkuI
         uNILtPpp+16I9V+5kkxAhpKFfStxOZTwLJmzs7smi5i5YuGxAO0GddKAC8vftrjzjngZ
         QalIPgDDPM1vhcaVLExKJfxIyZQSlxY7oRTIVuziAf1NVqS7u2krSzQyuSuFvFVEATfM
         cwiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZJSgJjZeJ5IQL+HnccCAIFoeicNK2pqTyfc/+9vcD3t9DyPohz
	5+VWyKNAUSgDziobngdW3cc=
X-Google-Smtp-Source: APBJJlHZTkDQZelSgmfbAKbs4oM+pfP01opAxg6tl34Ebd4hhrzHVBC1woQkBkiGkOKHAHxTPlnpwA==
X-Received: by 2002:a17:90a:f995:b0:268:13e2:fc91 with SMTP id cq21-20020a17090af99500b0026813e2fc91mr10263889pjb.31.1690858740799;
        Mon, 31 Jul 2023 19:59:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1895:b0:262:e619:f96c with SMTP id
 mn21-20020a17090b189500b00262e619f96cls3004567pjb.2.-pod-prod-09-us; Mon, 31
 Jul 2023 19:59:00 -0700 (PDT)
X-Received: by 2002:a17:90a:8c82:b0:268:5bc6:dc6e with SMTP id b2-20020a17090a8c8200b002685bc6dc6emr9133302pjo.42.1690858739888;
        Mon, 31 Jul 2023 19:58:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690858739; cv=none;
        d=google.com; s=arc-20160816;
        b=MBILHCwr3hiFMgLcBLdMbGoyg2PTXgKpi4Gmn2V5be4l1oGo0hXLDmSDwt6Kq5B38z
         mLRVH1rcQQ0U3K1zeqc2/j1NuWrxzVaH2nFAOUQV95AjGHdofK5InVJeaCy9F0ueC1lI
         8OZhTcja1yKa3OplBt+nGVVlEHNL07XqVoDltnwg5RAJQZV0S5dK4T3kgXMySAVevhSk
         Pv2CDDqzdkH0bNJOOGJBlUnMHrjuRlKhLAufkwmj1NiI26p1su0pITaNq0nI983GBdfF
         LJZqiO95OUni+75ufkXDdKy40u08XGpSJ1ZjoC3YrzrAt/5UlvAoz8UvKthygPSWGa1H
         Jhdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=/Jb/kXpyQFPlMGK5FsKg39jGJzqRtEYfgJWcYhPwYYg=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=yxYAgW79aZ2NhTrX87tkWloBcNsCSaUKodbgbBIJqt8OsIYlvPUmP7Nr+cULNWiDYi
         Rc7Vj4ooeIZ7ps6i3wF/q8WUlnp8Bp9kGfWTvbo2J0TPzAGGZpYoKMjD0Ay0JASIL14L
         xepZavhupuybBUnGLVjBQ5i4ggOoUfrmy4AxiuSiUt6tWw4mjUPcUce33dOKmnBVc+yz
         h0uAd6Dej0IWQ592iIYlm/rP5WpawOlOjo+3Ok8kIZ+OOPUuJaR04XS7vRZXnAiGzFar
         wIU822M6i8+yukF3i/G1+xC+4B224lquIcg5JaMEyM/Wl8li6/ADK7GiDK38SjriU76k
         zl8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id x19-20020a170902e05300b001bbb25dd3b3si577331plx.13.2023.07.31.19.58.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Jul 2023 19:58:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: dbb6d0eb178044d1b48d49b6a0948840-20230801
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:2a3c4814-1cd4-4922-9b73-84b27a04c4aa,IP:15,
	URL:0,TC:0,Content:0,EDM:-25,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,AC
	TION:release,TS:-25
X-CID-INFO: VERSION:1.1.28,REQID:2a3c4814-1cd4-4922-9b73-84b27a04c4aa,IP:15,UR
	L:0,TC:0,Content:0,EDM:-25,RT:0,SF:-15,FILE:0,BULK:0,RULE:EDM_GE969F26,ACT
	ION:release,TS:-25
X-CID-META: VersionHash:176cd25,CLOUDID:50beab42-d291-4e62-b539-43d7d78362ba,B
	ulkID:230801105845MU47NIPX,BulkQuantity:0,Recheck:0,SF:38|24|17|19|44|102,
	TC:nil,Content:0,EDM:1,IP:-2,URL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,
	OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_AEC,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,
	TF_CID_SPAM_FSI,TF_CID_SPAM_ULS
X-UUID: dbb6d0eb178044d1b48d49b6a0948840-20230801
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 452007182; Tue, 01 Aug 2023 10:58:42 +0800
From: Enze Li <lienze@kylinos.cn>
To: chenhuacai@kernel.org,
	kernel@xen0n.name,
	loongarch@lists.linux.dev,
	glider@google.com,
	elver@google.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: zhangqing@loongson.cn,
	yangtiezhu@loongson.cn,
	dvyukov@google.com,
	Enze Li <lienze@kylinos.cn>
Subject: [PATCH 4/4 v3] LoongArch: Add KFENCE support
Date: Tue,  1 Aug 2023 10:58:15 +0800
Message-Id: <20230801025815.2436293-5-lienze@kylinos.cn>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230801025815.2436293-1-lienze@kylinos.cn>
References: <20230801025815.2436293-1-lienze@kylinos.cn>
MIME-Version: 1.0
X-Original-Sender: lienze@kylinos.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as
 permitted sender) smtp.mailfrom=lienze@kylinos.cn
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

The LoongArch architecture is quite different from other architectures.
When the allocating of KFENCE itself is done, it is mapped to the direct
mapping configuration window [1] by default on LoongArch.  It means that
it is not possible to use the page table mapped mode which required by
the KFENCE system and therefore it should be remapped to the appropriate
region.

This patch adds architecture specific implementation details for KFENCE.
In particular, this implements the required interface in <asm/kfence.h>.

Tested this patch by running the testcases and all passed.

[1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html#virtual-address-space-and-address-translation-mode

Signed-off-by: Enze Li <lienze@kylinos.cn>
---
 arch/loongarch/Kconfig               |  1 +
 arch/loongarch/include/asm/kfence.h  | 66 ++++++++++++++++++++++++++++
 arch/loongarch/include/asm/pgtable.h | 13 +++++-
 arch/loongarch/mm/fault.c            | 22 ++++++----
 4 files changed, 93 insertions(+), 9 deletions(-)
 create mode 100644 arch/loongarch/include/asm/kfence.h

diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
index 5dbeb9b49ff7..b85ea4bf4a75 100644
--- a/arch/loongarch/Kconfig
+++ b/arch/loongarch/Kconfig
@@ -92,6 +92,7 @@ config LOONGARCH
 	select HAVE_ARCH_AUDITSYSCALL
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
+	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_SECCOMP_FILTER
 	select HAVE_ARCH_TRACEHOOK
diff --git a/arch/loongarch/include/asm/kfence.h b/arch/loongarch/include/asm/kfence.h
new file mode 100644
index 000000000000..d7db78a94b0f
--- /dev/null
+++ b/arch/loongarch/include/asm/kfence.h
@@ -0,0 +1,66 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * KFENCE support for LoongArch.
+ *
+ * Author: Enze Li <lienze@kylinos.cn>
+ * Copyright (C) 2022-2023 KylinSoft Corporation.
+ */
+
+#ifndef _ASM_LOONGARCH_KFENCE_H
+#define _ASM_LOONGARCH_KFENCE_H
+
+#include <linux/kfence.h>
+#include <asm/pgtable.h>
+#include <asm/tlb.h>
+
+static inline bool arch_kfence_init_pool(void)
+{
+	char *kfence_pool = __kfence_pool;
+	struct vm_struct *area;
+	int err;
+
+	area = __get_vm_area_caller(KFENCE_POOL_SIZE, VM_IOREMAP,
+				    KFENCE_AREA_START, KFENCE_AREA_END,
+				    __builtin_return_address(0));
+	if (!area)
+		return false;
+
+	__kfence_pool = (char *)area->addr;
+	err = ioremap_page_range((unsigned long)__kfence_pool,
+				 (unsigned long)__kfence_pool + KFENCE_POOL_SIZE,
+				 virt_to_phys((void *)kfence_pool),
+				 PAGE_KERNEL);
+	if (err) {
+		free_vm_area(area);
+		/*
+		 * If ioremap_page_range() failed, we have to restore
+		 * __kfence_pool to ensure that it can still free the
+		 * memblock allocated memory.
+		 */
+		__kfence_pool = kfence_pool;
+		return false;
+	}
+
+	return true;
+}
+
+/* Protect the given page and flush TLB. */
+static inline bool kfence_protect_page(unsigned long addr, bool protect)
+{
+	pte_t *pte = virt_to_kpte(addr);
+
+	if (WARN_ON(!pte) || pte_none(*pte))
+		return false;
+
+	if (protect)
+		set_pte(pte, __pte(pte_val(*pte) & ~(_PAGE_VALID | _PAGE_PRESENT)));
+	else
+		set_pte(pte, __pte(pte_val(*pte) | (_PAGE_VALID | _PAGE_PRESENT)));
+
+	preempt_disable();
+	local_flush_tlb_one(addr);
+	preempt_enable();
+	return true;
+}
+
+#endif /* _ASM_LOONGARCH_KFENCE_H */
diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index 716a7fcab15e..ff0c4ff34c0a 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -77,6 +77,12 @@ extern unsigned long zero_page_mask;
 	(virt_to_page((void *)(empty_zero_page + (((unsigned long)(vaddr)) & zero_page_mask))))
 #define __HAVE_COLOR_ZERO_PAGE
 
+#ifdef CONFIG_KFENCE
+#define KFENCE_AREA_SIZE	(((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 + 2) * PAGE_SIZE)
+#else
+#define KFENCE_AREA_SIZE	0
+#endif
+
 /*
  * TLB refill handlers may also map the vmalloc area into xkvrange.
  * Avoid the first couple of pages so NULL pointer dereferences will
@@ -88,11 +94,16 @@ extern unsigned long zero_page_mask;
 #define VMALLOC_START	MODULES_END
 #define VMALLOC_END	\
 	(vm_map_base +	\
-	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_SIZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE)
+	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_SIZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE - KFENCE_AREA_SIZE)
 
 #define vmemmap		((struct page *)((VMALLOC_END + PMD_SIZE) & PMD_MASK))
 #define VMEMMAP_END	((unsigned long)vmemmap + VMEMMAP_SIZE - 1)
 
+#ifdef CONFIG_KFENCE
+#define KFENCE_AREA_START	VMEMMAP_END
+#define KFENCE_AREA_END		(KFENCE_AREA_START + KFENCE_AREA_SIZE)
+#endif
+
 #define pte_ERROR(e) \
 	pr_err("%s:%d: bad pte %016lx.\n", __FILE__, __LINE__, pte_val(e))
 #ifndef __PAGETABLE_PMD_FOLDED
diff --git a/arch/loongarch/mm/fault.c b/arch/loongarch/mm/fault.c
index da5b6d518cdb..c0319128b221 100644
--- a/arch/loongarch/mm/fault.c
+++ b/arch/loongarch/mm/fault.c
@@ -23,6 +23,7 @@
 #include <linux/kprobes.h>
 #include <linux/perf_event.h>
 #include <linux/uaccess.h>
+#include <linux/kfence.h>
 
 #include <asm/branch.h>
 #include <asm/mmu_context.h>
@@ -30,7 +31,8 @@
 
 int show_unhandled_signals = 1;
 
-static void __kprobes no_context(struct pt_regs *regs, unsigned long address)
+static void __kprobes no_context(struct pt_regs *regs, unsigned long address,
+				 unsigned long write)
 {
 	const int field = sizeof(unsigned long) * 2;
 
@@ -38,6 +40,9 @@ static void __kprobes no_context(struct pt_regs *regs, unsigned long address)
 	if (fixup_exception(regs))
 		return;
 
+	if (kfence_handle_page_fault(address, write, regs))
+		return;
+
 	/*
 	 * Oops. The kernel tried to access some bad page. We'll have to
 	 * terminate things with extreme prejudice.
@@ -51,14 +56,15 @@ static void __kprobes no_context(struct pt_regs *regs, unsigned long address)
 	die("Oops", regs);
 }
 
-static void __kprobes do_out_of_memory(struct pt_regs *regs, unsigned long address)
+static void __kprobes do_out_of_memory(struct pt_regs *regs, unsigned long address,
+				       unsigned long write)
 {
 	/*
 	 * We ran out of memory, call the OOM killer, and return the userspace
 	 * (which will retry the fault, or kill us if we got oom-killed).
 	 */
 	if (!user_mode(regs)) {
-		no_context(regs, address);
+		no_context(regs, address, write);
 		return;
 	}
 	pagefault_out_of_memory();
@@ -69,7 +75,7 @@ static void __kprobes do_sigbus(struct pt_regs *regs,
 {
 	/* Kernel mode? Handle exceptions or die */
 	if (!user_mode(regs)) {
-		no_context(regs, address);
+		no_context(regs, address, write);
 		return;
 	}
 
@@ -90,7 +96,7 @@ static void __kprobes do_sigsegv(struct pt_regs *regs,
 
 	/* Kernel mode? Handle exceptions or die */
 	if (!user_mode(regs)) {
-		no_context(regs, address);
+		no_context(regs, address, write);
 		return;
 	}
 
@@ -149,7 +155,7 @@ static void __kprobes __do_page_fault(struct pt_regs *regs,
 	 */
 	if (address & __UA_LIMIT) {
 		if (!user_mode(regs))
-			no_context(regs, address);
+			no_context(regs, address, write);
 		else
 			do_sigsegv(regs, write, address, si_code);
 		return;
@@ -211,7 +217,7 @@ static void __kprobes __do_page_fault(struct pt_regs *regs,
 
 	if (fault_signal_pending(fault, regs)) {
 		if (!user_mode(regs))
-			no_context(regs, address);
+			no_context(regs, address, write);
 		return;
 	}
 
@@ -232,7 +238,7 @@ static void __kprobes __do_page_fault(struct pt_regs *regs,
 	if (unlikely(fault & VM_FAULT_ERROR)) {
 		mmap_read_unlock(mm);
 		if (fault & VM_FAULT_OOM) {
-			do_out_of_memory(regs, address);
+			do_out_of_memory(regs, address, write);
 			return;
 		} else if (fault & VM_FAULT_SIGSEGV) {
 			do_sigsegv(regs, write, address, si_code);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230801025815.2436293-5-lienze%40kylinos.cn.
