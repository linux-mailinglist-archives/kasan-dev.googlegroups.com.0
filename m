Return-Path: <kasan-dev+bncBAABBZVV7H7QKGQECAZZUZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 32EB92F41C1
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 03:28:56 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id 67sf183632otg.15
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 18:28:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610504935; cv=pass;
        d=google.com; s=arc-20160816;
        b=N5o7lfZf3g5DvlHsoCubSSYxYXXkbkySxlTkWjn077XOOyBJCuHrH1v6bzGdlG96tf
         /9Z4tiXXCGIsF1a+0HcxNbFIMRBk1zwzfeZXqrAF8oDozDXePGVGdQROaxs60PPrLQ3c
         o2oGyEI09xXH5EQ0grMJRCQhgIYx1GQKyTsxVl5lCrXBMfgO9JVlUVmulyLy19ZoLLc1
         iYr+SOyy9fRvRBKLCvFY1SrPRWYnAJzGAuHoZXXDGexAPnIehbhgaxyQ9vI7Q3UvMR6C
         Ram699TjKMIXNAl1U3HU9EYCnOla0T8+lyIDAlLOmdgGhq7mXogICL/IzAEYSCELxqEG
         GB6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7CALvY1lZZ548TVfuKu93WbiwC2BriTlID7Yw2muH/c=;
        b=JHu1LskB4zhv0m6QlVHUEKsRub2nVDalB4J/N0ksaYgOM2HHokxCFEomXg08I6/MiP
         FdezbpaPGsVLovPt/AlG0CNaHHfy/GIQwDLtyHb/J2wj6U7JARS6hAwH9GSlK01dc8gf
         rI6m20r2GZ6DAa2KXV8ykLvgn7QGLZq7OV+G+XE3A8NJ25LkDqtJhUBTJ3NWzy8ya8vt
         MOWor4vZnZeT6ry90JrRgUtyN0tFbYVwHkCJgTFnOhYI3VW2TDdf3QcfYJ/vjLHZveLZ
         0qFcj5qfRfsDim4HetVROs1BEt1JKTg6MmJbPFGASay2B4OzFxs0R1kdUdx0BuducE1i
         bHhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7CALvY1lZZ548TVfuKu93WbiwC2BriTlID7Yw2muH/c=;
        b=EmXOB4cqPpnuFjXH9uXYfuHwVW25rvokt4l42DEtzQJdz0E7eAwGEGJKdN0Xv1X07/
         FZnBiMKGB+6bgBmO6kptFRKvjzAvDNAB4+Yv2Nxb9gMz5MAOUkEwChBAMcbaqyHn+ZQ5
         4hgnzVUVC0jnDwdO63huGKl1m5y47GrenYZ2mKpS1nyLJ6I/s6rX6MNLYBjaEHQACWiX
         30Reea4mi31p2zrBx5RQRHAw3DPogfD1jvGlH9CvCbiYJJ+xB58YNPjQLXPky4/KXNuO
         h0AmjT1ILbYTlqsXUqr1UkcUxu4MCHgkDRdN/0sPhyOf4UowsHJuvYxzGxnkHcJmC4WG
         PMmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7CALvY1lZZ548TVfuKu93WbiwC2BriTlID7Yw2muH/c=;
        b=sBoJ/1+51WL9nJ/DgU8ztIkoi8EnCBjsUFR4z5Glvv1VnE9m1xz7MMRIAGwS5IDLCs
         bEtpt1VFfAnVHQ+V7sRpOB9Q6xKlQsxEDhvfndB9ZFMdW/pxO21FTjwaYuZdkBRoU3C7
         FTKtVWadn4s7699l6mXTcmOjAGHS8XcXRrbirtknW4GbddWnqeMWiTmIH2GoRxqyWr3a
         MyO5nvgZ4RQY47JDgDFXn7ymLmmOfcWobLxRXNY9NT5FqYwGzKi+08Lul1yNQMKo7lGc
         9k5npzhYepqDRH+hzoA3cL4b8PrUl97FKZkJlFOizCi2+++4rvvyTc+qUkD/ypao8kmK
         fxkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532cTaJxdCiD1M8fgEllqUKinixV8QpuNoEyc+VuW9QyzuQmNz60
	KBJEUrqCWBkHQHt7yfF/IjI=
X-Google-Smtp-Source: ABdhPJy5ObdH1vzgD74xS/zhoQXzHMFBr/HNBu6tGvwz0YS4GFX9++z4PX/SjtPHzWj5Pkin6KtjOA==
X-Received: by 2002:aca:c1d6:: with SMTP id r205mr30047oif.37.1610504935131;
        Tue, 12 Jan 2021 18:28:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:758a:: with SMTP id q132ls159886oic.4.gmail; Tue, 12 Jan
 2021 18:28:54 -0800 (PST)
X-Received: by 2002:aca:1a06:: with SMTP id a6mr31199oia.29.1610504934648;
        Tue, 12 Jan 2021 18:28:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610504934; cv=none;
        d=google.com; s=arc-20160816;
        b=PFEc09s3AGwI49OOywcT7W7pgkjToXviAP2DKB9tSGauejWDLDEyydVRVXvMe4E5xi
         LtXp65xjb8/ygus1wa/JY3JuJ+1uoepIdVcbzZerdAPZ7zUsmn3mhFOOK4mYEhJRL9lL
         b/fACJTYpLYOrqRfbCWU6LaYVmIZslqjkBNFrjEj41Mp19JAGf9sKSmoMW84ag2s99+h
         zmOcwVRS4kkK6/UKlsKUFZTo0hWW+P+gvZMNlrrqrU+K0SIYBifFtGRZNETlAM+J6X2o
         R06uX9uckX1sPLjoXK0fynpIqo6s602VgMAOlSsc+hRC874WBFl/XDDPqPT66Dr4RPxK
         8ssg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=8K2vjvGFwXzbsGBnQHMJDkfwmWttprDaTI3MY+9yp8s=;
        b=pq+kXmi2LzZ3VuFf9l8F3OC64WR38mc6hpqL1C/nVAdEB9N68mC4gG5IjFpmFIPD0d
         yinX1ikoiTZdlyoSw/L8vItcDy5dzmSoWjKEqVA2IWR2oqnWLBCb92nMR7qGecbi5O8w
         GQI2v7o8Bd5POOCiBwAxTUAFRFbSbWGK6KsQPJo9JT64hNtneaXvJEyMWk6+dU87vN0N
         ZHtGjzQvtf5zE3aIWHERGmEaas0uvcuxEhMAURGRqHUo9W7lANTPuvYpaeu1YyHsnFq2
         DSkn0iV2fwMhbVRN3YDm6x8b1Wq4E/tBKZgJlquaNaYZgRJwCwZ+bhuBpJBzWEzmjJlb
         aUSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
Received: from ATCSQR.andestech.com (exmail.andestech.com. [60.248.187.195])
        by gmr-mx.google.com with ESMTPS id l19si32162oib.3.2021.01.12.18.28.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Jan 2021 18:28:54 -0800 (PST)
Received-SPF: pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) client-ip=60.248.187.195;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id 10D2Pk8f039670;
	Wed, 13 Jan 2021 10:25:46 +0800 (GMT-8)
	(envelope-from nylon7@andestech.com)
Received: from atcfdc88.andestech.com (10.0.15.120) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.487.0; Wed, 13 Jan 2021
 10:28:27 +0800
From: Nylon Chen <nylon7@andestech.com>
To: <linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>
CC: <kasan-dev@googlegroups.com>, <aou@eecs.berkeley.edu>,
        <palmer@dabbelt.com>, <paul.walmsley@sifive.com>, <dvyukov@google.com>,
        <glider@google.com>, <aryabinin@virtuozzo.com>,
        <alankao@andestech.com>, <nickhu@andestech.com>,
        <nylon7@andestech.com>, <nylon7717@gmail.com>
Subject: [PATCH 1/1] riscv/kasan: add KASAN_VMALLOC support
Date: Wed, 13 Jan 2021 10:28:22 +0800
Message-ID: <20210113022822.9230-2-nylon7@andestech.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20210113022822.9230-1-nylon7@andestech.com>
References: <20210113022822.9230-1-nylon7@andestech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.120]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com 10D2Pk8f039670
X-Original-Sender: nylon7@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as
 permitted sender) smtp.mailfrom=nylon7@andestech.com
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

It's reference x86/s390 architecture.

So, it's don't map the early shadow page to cover VMALLOC space.

Prepopulate top level page table for the range that would otherwise be
empty.

lower levels are filled dynamically upon memory allocation while
booting.

Signed-off-by: Nylon Chen <nylon7@andestech.com>
Signed-off-by: Nick Hu <nickhu@andestech.com>
---
 arch/riscv/Kconfig         |  1 +
 arch/riscv/mm/kasan_init.c | 66 +++++++++++++++++++++++++++++++++++++-
 2 files changed, 66 insertions(+), 1 deletion(-)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 81b76d44725d..15a2c8088bbe 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -57,6 +57,7 @@ config RISCV
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if MMU && 64BIT
+	select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_KGDB_QXFER_PKT
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 12ddd1f6bf70..ee332513d728 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -9,6 +9,19 @@
 #include <linux/pgtable.h>
 #include <asm/tlbflush.h>
 #include <asm/fixmap.h>
+#include <asm/pgalloc.h>
+
+static __init void *early_alloc(size_t size, int node)
+{
+        void *ptr = memblock_alloc_try_nid(size, size,
+                        __pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, node);
+
+        if (!ptr)
+                panic("%pS: Failed to allocate %zu bytes align=%zx nid=%d from=%llx\n",
+                      __func__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
+
+        return ptr;
+}
 
 extern pgd_t early_pg_dir[PTRS_PER_PGD];
 asmlinkage void __init kasan_early_init(void)
@@ -83,6 +96,49 @@ static void __init populate(void *start, void *end)
 	memset(start, 0, end - start);
 }
 
+void __init kasan_shallow_populate(void *start, void *end)
+{
+	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
+	unsigned long vend = PAGE_ALIGN((unsigned long)end);
+	unsigned long pfn;
+	int index;
+	void *p;
+	pud_t *pud_dir, *pud_k;
+	pmd_t *pmd_dir, *pmd_k;
+	pgd_t *pgd_dir, *pgd_k;
+	p4d_t *p4d_dir, *p4d_k;
+
+	while (vaddr < vend) {
+		index = pgd_index(vaddr);
+		pfn = csr_read(CSR_SATP) & SATP_PPN;
+		pgd_dir = (pgd_t *)pfn_to_virt(pfn) + index;
+		pgd_k = init_mm.pgd + index;
+		pgd_dir = pgd_offset_k(vaddr);
+		set_pgd(pgd_dir, *pgd_k);
+
+		p4d_dir = p4d_offset(pgd_dir, vaddr);
+		p4d_k  = p4d_offset(pgd_k,vaddr);
+
+		vaddr = (vaddr + PUD_SIZE) & PUD_MASK;
+		pud_dir = pud_offset(p4d_dir, vaddr);
+		pud_k = pud_offset(p4d_k,vaddr);
+
+		if (pud_present(*pud_dir)) {
+			p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
+			pud_populate(&init_mm, pud_dir, p);
+		}
+
+		pmd_dir = pmd_offset(pud_dir, vaddr);
+		pmd_k = pmd_offset(pud_k,vaddr);
+		set_pmd(pmd_dir, *pmd_k);
+		if (pmd_present(*pmd_dir)) {
+			p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
+			pmd_populate(&init_mm, pmd_dir, p);
+		}
+		vaddr += PAGE_SIZE;
+	}
+}
+
 void __init kasan_init(void)
 {
 	phys_addr_t _start, _end;
@@ -90,7 +146,15 @@ void __init kasan_init(void)
 
 	kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
 				    (void *)kasan_mem_to_shadow((void *)
-								VMALLOC_END));
+								VMEMMAP_END));
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		kasan_shallow_populate(
+			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
+			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
+	else
+		kasan_populate_early_shadow(
+			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
+			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
 
 	for_each_mem_range(i, &_start, &_end) {
 		void *start = (void *)_start;
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210113022822.9230-2-nylon7%40andestech.com.
