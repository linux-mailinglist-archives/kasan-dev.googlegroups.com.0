Return-Path: <kasan-dev+bncBAABB7N532SQMGQEIVA6KFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id B90A9759047
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 10:29:50 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-635eb5b04e1sf16254476d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 01:29:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689755389; cv=pass;
        d=google.com; s=arc-20160816;
        b=yuuXsyUe75P6Dlm+VFLZATWbyfQlBkFKZlebmqtBpq6lvN+gjamrgsXpwB85xFXe3I
         B57Jw1gV7Aiqrc6HRBYaenDYcuviCEmhnD+tnEsfahW2zXNF/QX4CggyPtPblKgT6Rig
         iWrEgpzdg+sicEbIzLpbmFoNYZC8cxuk/XQT5pxyHeYfrQr+IQn2YukIgJ9A1vRsqpbQ
         RWnnqv17fXnhriGbhZ4Bb4wKMze/NONraHydfNBUCIbYPQboXG5hGw/B3e9cenB+NUrP
         KOdW42wKGD02VCuVqlJS6rd3afo4vJyn6YoLjB6dUIQXxRSI3ucM5IWIBFcz4KO4iUzK
         +z4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7WuXySDJa5AzuBJjEMwP2g8mo//Az5WppnW3vtCcQmc=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=c+Y9tEuidOMSFM68wMyZTSFP7NmhSmwF4dGkSTUa3xRTbpXfVh53xYTAj5uc/y6jT8
         83JkbzbPOLdFXuZvgk/CMW7rfchK63U3oUKHbWWfgt0NaX7CpY5+Q1jjdC4EY0/DDuKJ
         br/qaSxyJqjv64iE8lZUxyaBlA+kpINThV7xPCagpdHufd9VFHJqkYWu/7mLReHC1hEe
         gLO+UrB68PEzxtzFCPeXw/OkDnMg964TyxNnrN1a2/pRvlkPwp0WjYa+zw4LcBwjLkYk
         Bmg0cbykjf6ohjT+wq6rYTnVYFahsODoM1UDTxktJAuU40bgYAJO0vWlt/DpjB6oqJEt
         HHgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689755389; x=1690360189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7WuXySDJa5AzuBJjEMwP2g8mo//Az5WppnW3vtCcQmc=;
        b=ckp9QmkbBXgXP8DtwX0SCKPegylYD3/EocM2oIBxCRwAIxImdpPs6ht8UZcfd4gTW7
         n3BuUOf3R+Q0gINxgV51BxjpthOUNJ/tX87kcybTorEhd9MrAK9lYsb/WRkseEPEj6/e
         hf7lyG8bJSxQ1AZbSnP8lucVpypQzRLfgN+dOCHuXrQFFaNGBkfja88Y1C0skw5Tr573
         Y0unWOX6uvmBsgcTl9e7CINvy7f0tykCeOP+Pn4WJ+LlH2WJ6AHtqvnrPXtPe+V+LEnV
         +AeF5UoH6Jrjj/M9Kx3MpkEDZZLjWyEg29sRfDbMHp1USu4IEtN2WL+zbkgK+OCDWw81
         ksIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689755389; x=1690360189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7WuXySDJa5AzuBJjEMwP2g8mo//Az5WppnW3vtCcQmc=;
        b=lAe0u5SL1QfruhG9UvvHhvmu5r/FAOBSwoCf2Qc4dM8tWgCciA32eZrfaRbAdzB4QU
         OFXWnFL+zhiymY0HKA4WlGi42APdRwodn4LT2bpID7TsMHawHqmZHMYFlAeqVHimdReQ
         EasZRMfZjo168ojRC8jGePTLOX0rWfXgAdKhkT33/+BO7jCfeGwEm7Dtd4oUziEbsjbC
         WFGgh3RtI+BIRC2IGoAK9GBM1HarVtsryQ0ovCHEceaa4caUbIFs38YxHJ3lv4u99mUM
         ZmTHPH9Cr0pstvQZ0LsDx6Px6SEAv97JBXN/ZaI/lE0dxLx0GakKtYqVBOZGVg9wKcLu
         sO+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaiHAitAN74jInMY4+VRGS9sIWb91pGp3I+ICOM/cKXPxenb86O
	k7fBI7Sb9s3DKweaU1CLxXc=
X-Google-Smtp-Source: APBJJlHHGu8B4Sc8XdC++YmZzvpIM6arAXGAOM67497KH14imLBwAZHbTu00rfabzckQWqCqAWLexg==
X-Received: by 2002:a05:6214:c21:b0:635:da19:a680 with SMTP id a1-20020a0562140c2100b00635da19a680mr2511073qvd.2.1689755389524;
        Wed, 19 Jul 2023 01:29:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f413:0:b0:635:edc0:8015 with SMTP id h19-20020a0cf413000000b00635edc08015ls4623468qvl.0.-pod-prod-03-us;
 Wed, 19 Jul 2023 01:29:48 -0700 (PDT)
X-Received: by 2002:a05:620a:318c:b0:765:4418:cac7 with SMTP id bi12-20020a05620a318c00b007654418cac7mr1696798qkb.73.1689755388692;
        Wed, 19 Jul 2023 01:29:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689755388; cv=none;
        d=google.com; s=arc-20160816;
        b=aEGzKenivikg4AEHhWjlnsetpDByJpBS1l7TuVSjSxUhOQGEJlwSsUg1T8fqMdEf3/
         NSbpC7DZh3cT9Dkx4YnNhTiMQLjVXwgPEg6I+iiVS1butlKmaJkVP3DYkPWmRRKE1GyB
         mIKKEKhDd1L3A/5tHeSjhTGwFVtda6IEuS1UuAYIhT3cFID8/JIc+0+YbK/yvK5q0T2s
         iT6DhAxWLed48CY4CZxMX7axJWJEhsPERRhJsI/LSdBv/h2MuXQ6y1DD+eGwkqkzyzoL
         169Ntq7o9BfGSlIH70QTaCNNvNBG+LRi4SMurYmLaMlFaeSHjzt/YQ0ePW6ES5fBxdcr
         t/Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=6BHWIa283b/Th0rqzVskdqS/AWFs61+romNuWIS8H0w=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=E64iz0JYRTkM++tidrn0Z/mZfwzZaizCklHMf17QCs9uQGvjRcv/secw1YexpcY8cG
         Vh/PQWor9yOVpFSBs8pGrSZSJucg7jDHWEI9yjCuFGqlI+m6vTo7IpeoyCIXzIjrDqsj
         kw+TogXQIeCMbYQz8LbqAdRtIupZyociw5GPvXyBVWHQzzxox533CS2Y/AtxnOoeQVLN
         tlTxgbY2hU0XF8hAgBv+DqHVSm7rR4c/grTkur0+GIwi0NH3QQRuTvMd2fH+yP3N6xCK
         JCtOBiCBQsqZXLQSMzMvxzLNuBx3azFxne5G8jvDSBe+YxRXXh0AQSWyUOe1/IKxCMI/
         CBXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id dl11-20020a05620a1d0b00b0076821b38450si215095qkb.2.2023.07.19.01.29.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jul 2023 01:29:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: f0ed99f9d9174c4f8aab76592d27aee9-20230719
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:441d7fdd-754c-415a-95e2-9168bf32e60d,IP:25,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:10
X-CID-INFO: VERSION:1.1.28,REQID:441d7fdd-754c-415a-95e2-9168bf32e60d,IP:25,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:10
X-CID-META: VersionHash:176cd25,CLOUDID:b790e14c-06c1-468b-847d-5b62d44dbb9b,B
	ulkID:230719161451JTKHZIDM,BulkQuantity:1,Recheck:0,SF:38|24|17|19|44|102,
	TC:nil,Content:0,EDM:-3,IP:-2,URL:1,File:nil,Bulk:40,QS:nil,BEC:nil,COL:0,
	OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI,
	TF_CID_SPAM_ULS
X-UUID: f0ed99f9d9174c4f8aab76592d27aee9-20230719
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 633807358; Wed, 19 Jul 2023 16:28:19 +0800
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
Subject: [PATCH 4/4] LoongArch: Add KFENCE support
Date: Wed, 19 Jul 2023 16:27:32 +0800
Message-Id: <20230719082732.2189747-5-lienze@kylinos.cn>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230719082732.2189747-1-lienze@kylinos.cn>
References: <20230719082732.2189747-1-lienze@kylinos.cn>
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

Tested this patch by using the testcases and all passed.

[1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html#virtual-address-space-and-address-translation-mode

Signed-off-by: Enze Li <lienze@kylinos.cn>
---
 arch/loongarch/Kconfig               |  1 +
 arch/loongarch/include/asm/kfence.h  | 62 ++++++++++++++++++++++++++++
 arch/loongarch/include/asm/pgtable.h |  6 +++
 arch/loongarch/mm/fault.c            | 22 ++++++----
 4 files changed, 83 insertions(+), 8 deletions(-)
 create mode 100644 arch/loongarch/include/asm/kfence.h

diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
index 5411e3a4eb88..db27729003d3 100644
--- a/arch/loongarch/Kconfig
+++ b/arch/loongarch/Kconfig
@@ -93,6 +93,7 @@ config LOONGARCH
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN
+	select HAVE_ARCH_KFENCE if 64BIT
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_SECCOMP_FILTER
 	select HAVE_ARCH_TRACEHOOK
diff --git a/arch/loongarch/include/asm/kfence.h b/arch/loongarch/include/asm/kfence.h
new file mode 100644
index 000000000000..2a85acc2bc70
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
+static inline char *arch_kfence_init_pool(void)
+{
+	char *__kfence_pool_orig = __kfence_pool;
+	struct vm_struct *area;
+	int err;
+
+	area = __get_vm_area_caller(KFENCE_POOL_SIZE, VM_IOREMAP,
+				    KFENCE_AREA_START, KFENCE_AREA_END,
+				    __builtin_return_address(0));
+	if (!area)
+		return NULL;
+
+	__kfence_pool = (char *)area->addr;
+	err = ioremap_page_range((unsigned long)__kfence_pool,
+				 (unsigned long)__kfence_pool + KFENCE_POOL_SIZE,
+				 virt_to_phys((void *)__kfence_pool_orig),
+				 PAGE_KERNEL);
+	if (err) {
+		free_vm_area(area);
+		return NULL;
+	}
+
+	return __kfence_pool;
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
index 0fc074b8bd48..5a9c81298fe3 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -85,7 +85,13 @@ extern unsigned long zero_page_mask;
 #define MODULES_VADDR	(vm_map_base + PCI_IOSIZE + (2 * PAGE_SIZE))
 #define MODULES_END	(MODULES_VADDR + SZ_256M)
 
+#ifdef CONFIG_KFENCE
+#define KFENCE_AREA_START	MODULES_END
+#define KFENCE_AREA_END		(KFENCE_AREA_START + SZ_512M)
+#define VMALLOC_START		KFENCE_AREA_END
+#else
 #define VMALLOC_START	MODULES_END
+#endif
 
 #ifndef CONFIG_KASAN
 #define VMALLOC_END	\
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230719082732.2189747-5-lienze%40kylinos.cn.
