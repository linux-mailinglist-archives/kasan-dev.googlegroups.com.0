Return-Path: <kasan-dev+bncBCRKFI7J2AJRBJEVTCEQMGQEFODTM7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E6313F7193
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 11:17:35 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id r5-20020a92d985000000b002246fb2807csf13563253iln.18
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 02:17:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629883044; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zz8GF1OW+3YXl08nY7tjvG+I26VL6DUT+MJt3+sMrg164tADTIJFKCBeuFwVfEf9bz
         rp4qN/142VDIB+J/GwEb2L8qG3Q+8SJTB+PBDyN+kquV6gP3e8SWXJ/oXlT2begZj/nV
         nCqj1bTnEMm1Lr++QI2Hzpt/iFeGa1gvE1N2mmbHnE5+/xJ2WmtvwaM2i1yNJbcxKgb/
         gbkBM9UB/SVvKZOLipyKNuV3dUckz0dEhxfZb7Kxuk7O/LfaBlwiLwensOwxNpntTS8d
         9rw6O4u9OjrwM+PfUsgHzUS2zKsUSrCxUW+UahL7eXdZRqNNabD2vkK56LtvENmr2iH6
         Ermg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fgpl9Upn7PC64t+neD4e2Gn1mmA1mcBQK6mUtTe/Jbs=;
        b=R3mxcZrVaMLlq7sONwXbPX6bvXIud+GuJ/1Wmrppt5vJA9kxxA6lLeVFuisJg4AOv3
         h19jf4iDB3HZPaSA5YL6IimQqEL/GUH8HoCklytS7c89cQTUNxedRAGQl54rlh0If5Bx
         zR8xKnziNF+q3M1sutDf7lBAAtRaaeBZCKu1AL+xaZLyCOgjFoW71fdQ9A8obRK64rkE
         UkEJCKa4t7eJ7gip40YsNtYZbt8E2pXdHBdQXrf1I8glCP75/OVM7OidMHclAWeIFVJy
         df5H8U7TYyeV+0HJdKehgaiB56kU8vbjK2jDrV0oehzz7jF05v/B1OQLECbrtp4gKseo
         +Aow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fgpl9Upn7PC64t+neD4e2Gn1mmA1mcBQK6mUtTe/Jbs=;
        b=SBHlqWZwVm7hDxJ6ptuDi6g5xVf09CDXJpUSjHguvB64EVK38RJgSZ1j8xZfEXXtDL
         yu1DjwLc+E3KSGYHk7v3rMUBY1TgTU6IQkF8dKrWGCR8quirLGMVovFKjG71i7o6oJlY
         JA33KXWDfaW6PQ1eqjddA/MlUucf6AUl9oHjCKH+YnnIGGUzc7QaLVX+iKadadb81TPF
         KQc4vEWLBQ3NJBjKqm11pCPXu7a8DjMIIxShQOPg6rtGpEk4aH8dBx+pjrVk7qFHUY84
         77y71H2wijhZr53+am+NhtYUfQQluKMJuc1eykmEFRv+4ShdDHAiVKdz5J/hC3JcH+xj
         MqKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fgpl9Upn7PC64t+neD4e2Gn1mmA1mcBQK6mUtTe/Jbs=;
        b=cTG3v/M5tekR+n56C3ATPbA69qIprQ0xonHQ0TSoXkjIDe57NOiCn+gc3JPeKhSDv3
         aWJoMXRTP9amV1h2EFv+clcGg/eZCJvWOt2lI6XlBXwKoZLumrmu1Pjx+MNhPT3ih0gD
         UlXEWlaZI6MiC+FqrgBLB/bZSEhyUrGqnxYKNhNSW1ZLUq+58tS0DZ2G9IS5+RAsGVGJ
         3DkXd6CKHcjkXodgpdMEp6bIvEgQ4Q35aT0qLzfYJOWgIlCdtZzaD0tP2S9STgqLS9j+
         bOF29R29CIghGKKDKxqWojgqSilIZ7oWWU705OnEWtB9OjNv5epKhZEwjnyDYzewr1/I
         T8Aw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531pvkj8YXCVUXaax0DtxNWCf9+LoHRrZLK+Ijq1krwHCOdLMudq
	tc5B3Z+aoCv9bYAFb2zkWE4=
X-Google-Smtp-Source: ABdhPJwn/PT3fZzgQQUOzne+5/CeFSeROWYpEZWiWRfGof+c1YzBs/fOqLZiWIFvTyKPIUtL9/BHVQ==
X-Received: by 2002:a05:6e02:ee1:: with SMTP id j1mr28484737ilk.61.1629883044407;
        Wed, 25 Aug 2021 02:17:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ca8c:: with SMTP id t12ls342140ilo.7.gmail; Wed, 25 Aug
 2021 02:17:24 -0700 (PDT)
X-Received: by 2002:a92:7b0c:: with SMTP id w12mr30540194ilc.307.1629883044070;
        Wed, 25 Aug 2021 02:17:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629883044; cv=none;
        d=google.com; s=arc-20160816;
        b=POKKNKY01xI5nnPievVuJQJXAzNmJCWKlrL1YdP4Cm3o9tnwQZnxP6NWX5JAmjdoYK
         eiZyzsZyV1gfLg0EmKjIN/rcu80SSLhVzDUC7vJr3aPjDzpiagydagQjrkBEdoOA7Rtv
         Y6mMxgP630fW5ftVfnHKk2DylTpz6Gb8ZwRs8qE5Eq1C5wmKmLp6NhYfaP6nmRF4LJQK
         P5FNjmybMI+LCnU++bnwFSKCKId0EE+tJPbABnCGtUvQ9Jhs0vI5kLiSChY9bjtTvJ9y
         paHe1jqzTunUKlDA5Bjnh8LIzZlw092+MLEMEsPVRqndNoYmWW3OOVS8CjL9n36TspyW
         Sc1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=x5YYx0apQR+eDUeXNtV6ji9xtv18+uPcHeqTHwfQsCc=;
        b=zKfghR63XVc3QjpF+vcZ0u9h31qpG6Pq/i+vjZ1BtmPU2zjeXbPj/kSxmRwsiCdAF0
         rMahgmLkb/daEbCvxAxZ7vDAJ3CNk5LO+zRnTHF7ePeSvHNatnI0w7rjXrPpxJWQy0B1
         qLf6+qrXVYueo0sSg+Ik/auWh53WQRNF1YQJI+74I+Vjf57d9RsZamMtW0aDIxT1kgrD
         pNv3+/+DU+6j+mm8pluLz4WNEYk54tRgeObUyH1PEK+RivEU6/HHuOFi/SkwdDPllcw/
         4zXRjSQTxcvgKOrnU1Q0N2/iX9IkHgcUhQuDFr8j5AT7uCBLFQy/CV46B8eXJfAB7wXa
         nvhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id z12si231692iox.0.2021.08.25.02.17.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Aug 2021 02:17:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4GvgN10WvBz1DDJK;
	Wed, 25 Aug 2021 17:16:49 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 17:17:22 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 17:17:21 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Russell King <linux@armlinux.org.uk>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH 3/4] ARM: Support KFENCE for ARM
Date: Wed, 25 Aug 2021 17:21:15 +0800
Message-ID: <20210825092116.149975-4-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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
KFENCE on ARM. In particular, this implements the required interface in
 <asm/kfence.h>.

KFENCE requires that attributes for pages from its memory pool can
individually be set. Therefore, force the kfence pool to be mapped
at page granularity.

Testing this patch using the testcases in kfence_test.c and all passed
with or without ARM_LPAE.

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 arch/arm/Kconfig              |  1 +
 arch/arm/include/asm/kfence.h | 52 +++++++++++++++++++++++++++++++++++
 arch/arm/mm/fault.c           |  9 ++++--
 3 files changed, 60 insertions(+), 2 deletions(-)
 create mode 100644 arch/arm/include/asm/kfence.h

diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 7a8059ff6bb0..3798f82a0c0d 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -73,6 +73,7 @@ config ARM
 	select HAVE_ARCH_AUDITSYSCALL if AEABI && !OABI_COMPAT
 	select HAVE_ARCH_BITREVERSE if (CPU_32v7M || CPU_32v7) && !CPU_32v6
 	select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL && !CPU_ENDIAN_BE32 && MMU
+	select HAVE_ARCH_KFENCE if MMU
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
diff --git a/arch/arm/include/asm/kfence.h b/arch/arm/include/asm/kfence.h
new file mode 100644
index 000000000000..eae7a12ab2a9
--- /dev/null
+++ b/arch/arm/include/asm/kfence.h
@@ -0,0 +1,52 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef __ASM_ARM_KFENCE_H
+#define __ASM_ARM_KFENCE_H
+
+#include <linux/kfence.h>
+#include <asm/set_memory.h>
+#include <asm/pgalloc.h>
+
+static inline int split_pmd_page(pmd_t *pmd, unsigned long addr)
+{
+	int i;
+	unsigned long pfn = PFN_DOWN(__pa((addr & PMD_MASK)));
+	pte_t *pte = pte_alloc_one_kernel(&init_mm);
+
+	if (!pte)
+		return -ENOMEM;
+
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		set_pte_ext(pte + i, pfn_pte(pfn + i, PAGE_KERNEL), 0);
+	pmd_populate_kernel(&init_mm, pmd, pte);
+
+	flush_tlb_kernel_range(addr, addr + PMD_SIZE);
+	return 0;
+}
+
+static inline bool arch_kfence_init_pool(void)
+{
+	unsigned long addr;
+	pmd_t *pmd;
+
+	for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
+	     addr += PAGE_SIZE) {
+		pmd = pmd_off_k(addr);
+
+		if (pmd_leaf(*pmd)) {
+			if (split_pmd_page(pmd, addr))
+				return false;
+		}
+	}
+
+	return true;
+}
+
+static inline bool kfence_protect_page(unsigned long addr, bool protect)
+{
+	set_memory_valid(addr, 1, !protect);
+
+	return true;
+}
+
+#endif /* __ASM_ARM_KFENCE_H */
diff --git a/arch/arm/mm/fault.c b/arch/arm/mm/fault.c
index f7ab6dabe89f..9fa221ffa1b9 100644
--- a/arch/arm/mm/fault.c
+++ b/arch/arm/mm/fault.c
@@ -17,6 +17,7 @@
 #include <linux/sched/debug.h>
 #include <linux/highmem.h>
 #include <linux/perf_event.h>
+#include <linux/kfence.h>
 
 #include <asm/system_misc.h>
 #include <asm/system_info.h>
@@ -131,10 +132,14 @@ __do_kernel_fault(struct mm_struct *mm, unsigned long addr, unsigned int fsr,
 	/*
 	 * No handler, we'll have to terminate things with extreme prejudice.
 	 */
-	if (addr < PAGE_SIZE)
+	if (addr < PAGE_SIZE) {
 		msg = "NULL pointer dereference";
-	else
+	} else {
+		if (kfence_handle_page_fault(addr, is_write_fault(fsr), regs))
+			return;
+
 		msg = "paging request";
+	}
 
 	die_kernel_fault(msg, mm, addr, fsr, regs);
 }
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210825092116.149975-4-wangkefeng.wang%40huawei.com.
