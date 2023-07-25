Return-Path: <kasan-dev+bncBAABBPGR7WSQMGQEM2ZND3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id EF53C760A20
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 08:16:29 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4053a03d5b2sf68316921cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jul 2023 23:16:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690265789; cv=pass;
        d=google.com; s=arc-20160816;
        b=WQbuvhPcmvi3kPdzdNzJo+u1TPId6z9wLCWNEaMaJgMgaJn6HPERNiRqC87IFH0WpI
         geoHqf69nzUTR7kipYA5ViGcTuAWsNSi018UrNsK0fomSl9G5ePQIB8dXuq3tRRIYhmk
         90vnzCxOOIrw6FWACGabXxBpF7+luCngYuUaJUi3FObx2NwwqAhf3PmqQzAAPPi2pKF/
         j2iv5tId+QMf3Fq9vSII/OUAbqptbbPRONvC5azyCtrMcaVhmd6RMkZg3mANOwQSUAPC
         aC2P7NQy2uBVNWa+C/0czBUT5DXZb4JL2IbOJdc8Et/5S2IgFWmlxNLkHDkwjAxF3N3u
         ZAvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=UgG+8ZTNfcjilv7gw9ig5tW+JI44MdiJwsiYe2Wp7F8=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=Wgj3gLqwpQ2Xg9ILs+suT0P1x1C4Lpue5IReQXjcnlbxWQ58p8gt3/cijsgYo2cV3A
         7LlpdTIxr+ecJY0lfN8jT4qtvn4/BF5wcuFXaMms6IORsBBXB4E4qSQCpiLeZf+7+0Nr
         0KPT7q2DR9LgbzQMrv8F5qh1jjA+ljWwIlS3MhRbKhApa9w87NTtrC4v07npsVn7TW7j
         AFBtXKnypeBtvkMl7fdl8SLmARsb738rmz1Nl+ylhwdv2bJNovo/tzoSgiL2Q1ZIxWkS
         RvVn6HHe+YSVkL/mn8XVLaPZvPuBWXRL9JTeODmvn35NeYSq3AG2e6FWlJFQhlhCQFae
         p22Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690265789; x=1690870589;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UgG+8ZTNfcjilv7gw9ig5tW+JI44MdiJwsiYe2Wp7F8=;
        b=scwGmv6QQW3MlxaYSyyKIz5ZUlv0/mg2LiQJdYkvCw2wO+HtWiOdb7v6e2neaGhd+v
         z8AH8xUunYypy7hkyrk44YhZt3azQf0CLbpcY4WegvpNls5qzhSOCqTTZ+POS+j2OY1q
         vl/OtMsmWYBKnSvJNMpqQf/rQKlHrdUwxiYBgj13p5xng5kp8gOzecxsQh4Thw1dKi78
         DbXzQFMa1hGoSQ7P0gOBFNHCOhHQyIDgTSZOMbaS1yte1y2aBOjthJckFVZxmspVt0bl
         9Z6POSIKhv9/YnmyXPUAdJq1qlXu1wxMU9TwVwXjcHnxjsxo7tjb0uM3Pcq9Wr1eJAkF
         aABg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690265789; x=1690870589;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UgG+8ZTNfcjilv7gw9ig5tW+JI44MdiJwsiYe2Wp7F8=;
        b=Q0cdvqGXNkOFVgwk3fbTke5cffyiczGfz69bgLwtVm3+7+G8UFalnetlVGNQPw9zy3
         pkXxqU3zl8AdvM+vgc+bSStOxYvZbyyJ2JH55VMxCN7Gs8F9OMILOZwZ4LO/KxGsIo/f
         4FWfpF9BGV1BqMmgxbx05GetuGAyTgN56SMJFsBPrI7wJ35H281L7rnTRZDmKGOiH0jn
         +QPYayOlA9m5fix5yO55u4B6DqaKbrfdR3mA2UNz23eL0fuldav6P8dmHSfsoCTLp01n
         kCNokieNsZmkKJFxaUnuThmxtJtQgqtfwHxMtMGnqndPm+3Lzn6WflQxnMSQ9Hg7WfuD
         wbgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZobCpVf9OtI3F75zVLrp1hn5reUd3FpdLOFOTZd9p00oTWVMS4
	roa5RJRpwJgXKoJX+bJ+8+O5TA==
X-Google-Smtp-Source: APBJJlF5jgXfRdEMnXUNz8AiovFlTc9BDF2NvMoBe+MNZuAi5bN4dT79NvYGOWTWRQvQulPT9Gw8NA==
X-Received: by 2002:a05:622a:130d:b0:403:e1d1:8b91 with SMTP id v13-20020a05622a130d00b00403e1d18b91mr2581948qtk.60.1690265788616;
        Mon, 24 Jul 2023 23:16:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7355:0:b0:403:ad49:7362 with SMTP id q21-20020ac87355000000b00403ad497362ls6853599qtp.2.-pod-prod-07-us;
 Mon, 24 Jul 2023 23:16:28 -0700 (PDT)
X-Received: by 2002:a05:620a:f0f:b0:768:1394:45e5 with SMTP id v15-20020a05620a0f0f00b00768139445e5mr1937425qkl.12.1690265788117;
        Mon, 24 Jul 2023 23:16:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690265788; cv=none;
        d=google.com; s=arc-20160816;
        b=acxlmY9WPYaLTFlnAScSS+uLlyfSiV0IkqFIcnxT9HrQPVyvGxzmoDpDRzOdnSeTbn
         3g2HpJZwNaJCaFE7Im8pCmTHIfk5MjhPLaxtPXeX+mDmAVA4KoELjfXC0pWzmfpo4U9e
         +JGcPqMDAv16Ne9v7aSaFLW18jQrmuJqIyzyPymKe/U3E6BKCE7WVGroTVm/B2HfeQiW
         MQ8mRCmTD4RqY2WYV0aPfLVmPHeNjhMprQ5+yCnuh7qv1mZdwRDs6rimdJevp0bazFq9
         Oz09GDbbvMLF/4EkETBbCl/zLq6W9aosHbpnV1fDwBZlsoTTVqjXtgtKrpntUOO0KFKY
         9hDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=EqW6kJ87jfc/UoorJHCNkGGBtCR16wyXTZDbfFoAbyY=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=ftQSB1XI+iF1l3yOclUX9H8I+rrrN5qU87ub8VUHlIAhEPH0aQuSAV+LAxoHkX/0MU
         HzpF5hB2rSlbFcmrtlGoBVMyEAB9LusAZ2aAN6+e5ZbnjG2GYUf1C8byTJREjLAems/r
         Q9r9sRG9lJYV9uSFBYqX6wxoauxF57ltqDVbHOfIrPy+mXSM6MsDXoh5UQJBL53llvD9
         KR2YSrbR+pbZlWHhmDujP3YH0NIspvatd/0UHINvZtlt7BVvWZGqKukVAlVA/Saa661I
         +TAYXwdpfK8jrMlNfZkFHwEDb9DNv2MlGPtx8AAwRtURkP0uD5UXndT+Aifu6Idqquq1
         MGDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id ob14-20020a0562142f8e00b006363f2c380bsi722573qvb.7.2023.07.24.23.16.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jul 2023 23:16:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 3f0d37b293b84437aff8eecdace72e24-20230725
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:d8a88afa-7b8d-4f33-a7ea-af79e1cee8d2,IP:15,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:0
X-CID-INFO: VERSION:1.1.28,REQID:d8a88afa-7b8d-4f33-a7ea-af79e1cee8d2,IP:15,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:0
X-CID-META: VersionHash:176cd25,CLOUDID:1d6ec1b3-a467-4aa9-9e04-f584452e3794,B
	ulkID:230725141514S69XBC26,BulkQuantity:0,Recheck:0,SF:38|24|17|19|44|102,
	TC:nil,Content:0,EDM:-3,IP:-2,URL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0
	,OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_ULS,TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,
	TF_CID_SPAM_FSI
X-UUID: 3f0d37b293b84437aff8eecdace72e24-20230725
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 755063753; Tue, 25 Jul 2023 14:15:12 +0800
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
Subject: [PATCH 4/4 v2] LoongArch: Add KFENCE support
Date: Tue, 25 Jul 2023 14:14:51 +0800
Message-Id: <20230725061451.1231480-5-lienze@kylinos.cn>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230725061451.1231480-1-lienze@kylinos.cn>
References: <20230725061451.1231480-1-lienze@kylinos.cn>
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
 arch/loongarch/include/asm/kfence.h  | 62 ++++++++++++++++++++++++++++
 arch/loongarch/include/asm/pgtable.h | 14 ++++++-
 arch/loongarch/mm/fault.c            | 22 ++++++----
 4 files changed, 90 insertions(+), 9 deletions(-)
 create mode 100644 arch/loongarch/include/asm/kfence.h

diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
index 70635ea3d1e4..5b63b16be49e 100644
--- a/arch/loongarch/Kconfig
+++ b/arch/loongarch/Kconfig
@@ -91,6 +91,7 @@ config LOONGARCH
 	select HAVE_ARCH_AUDITSYSCALL
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
+	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_SECCOMP_FILTER
 	select HAVE_ARCH_TRACEHOOK
diff --git a/arch/loongarch/include/asm/kfence.h b/arch/loongarch/include/asm/kfence.h
new file mode 100644
index 000000000000..fb39076fe4d7
--- /dev/null
+++ b/arch/loongarch/include/asm/kfence.h
@@ -0,0 +1,62 @@
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
+	/* Flush this CPU's TLB. */
+	preempt_disable();
+	local_flush_tlb_one(addr);
+	preempt_enable();
+
+	return true;
+}
+
+#endif /* _ASM_LOONGARCH_KFENCE_H */
diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index 98a0c98de9d1..2702a6ba7122 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -77,6 +77,13 @@ extern unsigned long zero_page_mask;
 	(virt_to_page((void *)(empty_zero_page + (((unsigned long)(vaddr)) & zero_page_mask))))
 #define __HAVE_COLOR_ZERO_PAGE
 
+#ifdef CONFIG_KFENCE
+#define KFENCE_AREA_SIZE \
+	(((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 + 2) * PAGE_SIZE)
+#else
+#define KFENCE_AREA_SIZE	0
+#endif
+
 /*
  * TLB refill handlers may also map the vmalloc area into xkvrange.
  * Avoid the first couple of pages so NULL pointer dereferences will
@@ -88,11 +95,16 @@ extern unsigned long zero_page_mask;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230725061451.1231480-5-lienze%40kylinos.cn.
