Return-Path: <kasan-dev+bncBC447XVYUEMRBIPP4SAQMGQEF6ALEEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id A9C963266A1
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 19:02:09 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id k16sf388939ejg.9
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 10:02:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614362529; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zl4xwZnGjVjYGhqeQUSWfYIGKSjlMQJPaWXcS8Wt7buuycsFb7tENtY0Pjc0sKYHse
         wtvdI7U7fYJ07KZiwJn3a+nJxW6AVX12jU+7GcM1HqHUfBS1jtC6voTqK+y0A2Rxpxzp
         94jcNf1ERNHnfNB98XEyob5vN6e34sXH0MpC/OCZ1lJ5+oNLmJ6wPEO0w3el4rFVENEz
         3+9Ml1iUgBsLuRBUcekXR4hyzE7oeATlkghorChV6FghSu6DDfKlH4d/hS3hhPlBn0Hp
         Ue055MFG/s73CCgtcMZTo/PRswPKYwE0IOaIp84v1WLJ6m41hpBXoTLqlA8EABRnN6h8
         aKdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=hbb1tL+dvkHn8mEf5SsdmEviXRIfb04pc1LYNvBUQFA=;
        b=ZoB2ut8prJKycISQvy6c2bsAKqCV/fRH5C/Z9Bs0XxIqCF/nvDwEmU6UE35ehUEPkW
         w+WHVhjq/HD7QbK3k+QMr/s2bDsYQxqVQSoyZ18HNtiZENtg6rlJwJVF/rcCgzNhMULf
         VTRToq94OKdvsBoa0Nekyr37J1qgo4If7qNxISn7TYnPGrwM/QuSQ5jFJLyczaltWu0b
         2URNRAmvmoniniSWKst4V0q/QnNN8hw5DHmCkXbBXWacQbQ5wQgxUV5aXCbwbgyLliWV
         x7/5Wwu0Hjos2QVZ9CILD+JGFSlZV8DEPWR2fm8X5uAXNheIdi16lbxv1y8qKw2RZy0Z
         D8wA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hbb1tL+dvkHn8mEf5SsdmEviXRIfb04pc1LYNvBUQFA=;
        b=cByoTD3xwWDr6pPIlmMd5/jXq1tsPdhluCW1v1VA5P00OQ4BQX3Y1Fgbmg5DE4ppya
         jLyiJ/zMvvRH2y4D/TyM/Dul0VQkNuN8q/CbAoQM+bSnUNHgQL7lqbaMZ7xOQmJVIkO7
         BH56dzjr0zK8NXfnzbJC/4X4nInS3+j0LFqwXIwh7OZbUw9S8OjALEmveXxGVM+pxJiP
         YTi2dgYU4z8BuIY0+mew/lJCJ5xJgmCciiH+d95lsGw7GKKSximNRAVQr09AC+P+3ICF
         +b5bpy0q9WL2jNIarwotJCZ+5tD0sXu1EvkvLEZpst68kps/JFB3ZSK9PM7M5+UrrP6X
         MRfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hbb1tL+dvkHn8mEf5SsdmEviXRIfb04pc1LYNvBUQFA=;
        b=uCCUEj05URBda9ft4Jl3TRb16FGQERc1NG9g9VzTcsQTTrQBZJCc6kdEYDXuWNFVcj
         PL1uCfiCUaxHfZ/ZgScDYs2vX8fSlXtOr49oXOW5P0HaDuRMXQbdqIXH6LMW5rZ2xyxY
         WYbGfg+lOOPkjnvRRcFrW5c75jAiMb8T0npdofdcnAu4n7PPYz3QqmcEz7Wc3yPWT+fL
         KdTOB52MSr0f2WDLFCMIcwWx+AFwDambghi+4lYCP8Ag7YLPzJoN6kCtk7XOl0SFrtCB
         ltt3n2HMapmjWpV/3o/hiTAZypNHa39NDTaMOtzNePQ/t80H46ssLQ67q6ZsL1ex4C8H
         oRDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530d//MkwxxGp7HlWRXIukuCPUhQiDWPz/Jvj2r5E/8oadjV/F+C
	BhbqyeCheB/sUxAsshxJY00=
X-Google-Smtp-Source: ABdhPJwzlPvB03EPdt7xvEKrjUPhPIIJVjUQLTAiH2151n8AfajPBJ4VKlibF5i0bVY4zqR3K2rB4Q==
X-Received: by 2002:a17:906:7e42:: with SMTP id z2mr4680465ejr.177.1614362529421;
        Fri, 26 Feb 2021 10:02:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:520e:: with SMTP id s14ls834073edd.3.gmail; Fri, 26
 Feb 2021 10:02:08 -0800 (PST)
X-Received: by 2002:aa7:da19:: with SMTP id r25mr4860059eds.367.1614362528631;
        Fri, 26 Feb 2021 10:02:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614362528; cv=none;
        d=google.com; s=arc-20160816;
        b=Zm9l0A/liP+CNKsQaa1c8JpJbr0vTscSN3k5gpSLdZxIilsbLeCpkYSpCrawJmB/xB
         HHbWq27fSSM5ufQdOTfSPjXD6yXDS9AyltGKs3z7QgRP0y2EZ8P9D2AtwtYLQz3gZLXJ
         Hz684Gt7gpbjmPj/+fwEuDFQxJ3+NxfRpGwOCZYrSkOMHwpLqCnggFakxr9k0aj6/XQR
         NAwqzhl0WBhd8xnoGrAjmq/33hTohZ7hj7l9aMIloS4JXXGjcd4+0bS84AtoX5rz3UOF
         B7b+7sOnaKWq91r/FMTxa9ygw+TVs0O0kppj/x1ome1sU5QFHtG7x0V7k1jn9vrSRDdE
         8f2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=wtVhhSACxrBZ1RpGpdjSEdxD6z3ujgmu3ukxhj4wRUU=;
        b=R7FKHbP38lIjptgzjRCNzyyUgfdnFZzjkr+5Dq6Q5XVTq6kHk8w6G3kAmdeL1kga0z
         hLXqO3vGNc1HAvA0SLLocUmVZXYAGYI8+XQqn/itDYcRQ3/gWp62LOmH942QbssQ6DXr
         bgcfltMsfj6Q17dxrhlRwxO98escjiG3VH2wwvrLv8JPD+Nax6KiX/ukn6CJAYvQ/Yjl
         VHrpTtZd0RX+8VU0VPJ6aVlU495MvooE7ioiDlg8OoQDFMPKGh/fW9s9s2ia8nUMXW+Y
         xPwv9xk5MQlykZTK4pRyKIsutcqGb740Je2gY/EkbUPTb0igwuGDTJVMvmtveifu+CrF
         KPOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay4-d.mail.gandi.net (relay4-d.mail.gandi.net. [217.70.183.196])
        by gmr-mx.google.com with ESMTPS id p3si472294edq.4.2021.02.26.10.02.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 26 Feb 2021 10:02:08 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.196;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay4-d.mail.gandi.net (Postfix) with ESMTPSA id 1F829E000B;
	Fri, 26 Feb 2021 18:01:55 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Nylon Chen <nylon7@andestech.com>,
	Nick Hu <nickhu@andestech.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH v2] riscv: Improve KASAN_VMALLOC support
Date: Fri, 26 Feb 2021 13:01:54 -0500
Message-Id: <20210226180154.31533-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.196 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

When KASAN vmalloc region is populated, there is no userspace process and
the page table in use is swapper_pg_dir, so there is no need to read
SATP. Then we can use the same scheme used by kasan_populate_p*d
functions to go through the page table, which harmonizes the code.

In addition, make use of set_pgd that goes through all unused page table
levels, contrary to p*d_populate functions, which makes this function work
whatever the number of page table levels.

And finally, make sure the writes to swapper_pg_dir are visible using
an sfence.vma.

Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
---

Changes in v2:                                                                   
- Quiet kernel test robot warnings about missing prototypes by declaring         
  the introduced functions as static.

 arch/riscv/mm/kasan_init.c | 61 +++++++++++++-------------------------
 1 file changed, 20 insertions(+), 41 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index e3d91f334b57..aaa3bdc0ffc0 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -11,18 +11,6 @@
 #include <asm/fixmap.h>
 #include <asm/pgalloc.h>
 
-static __init void *early_alloc(size_t size, int node)
-{
-	void *ptr = memblock_alloc_try_nid(size, size,
-		__pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, node);
-
-	if (!ptr)
-		panic("%pS: Failed to allocate %zu bytes align=%zx nid=%d from=%llx\n",
-			__func__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
-
-	return ptr;
-}
-
 extern pgd_t early_pg_dir[PTRS_PER_PGD];
 asmlinkage void __init kasan_early_init(void)
 {
@@ -155,38 +143,29 @@ static void __init kasan_populate(void *start, void *end)
 	memset(start, KASAN_SHADOW_INIT, end - start);
 }
 
-void __init kasan_shallow_populate(void *start, void *end)
+static void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned long end)
 {
-	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
-	unsigned long vend = PAGE_ALIGN((unsigned long)end);
-	unsigned long pfn;
-	int index;
+	unsigned long next;
 	void *p;
-	pud_t *pud_dir, *pud_k;
-	pgd_t *pgd_dir, *pgd_k;
-	p4d_t *p4d_dir, *p4d_k;
-
-	while (vaddr < vend) {
-		index = pgd_index(vaddr);
-		pfn = csr_read(CSR_SATP) & SATP_PPN;
-		pgd_dir = (pgd_t *)pfn_to_virt(pfn) + index;
-		pgd_k = init_mm.pgd + index;
-		pgd_dir = pgd_offset_k(vaddr);
-		set_pgd(pgd_dir, *pgd_k);
-
-		p4d_dir = p4d_offset(pgd_dir, vaddr);
-		p4d_k  = p4d_offset(pgd_k, vaddr);
-
-		vaddr = (vaddr + PUD_SIZE) & PUD_MASK;
-		pud_dir = pud_offset(p4d_dir, vaddr);
-		pud_k = pud_offset(p4d_k, vaddr);
-
-		if (pud_present(*pud_dir)) {
-			p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
-			pud_populate(&init_mm, pud_dir, p);
+	pgd_t *pgd_k = pgd_offset_k(vaddr);
+
+	do {
+		next = pgd_addr_end(vaddr, end);
+		if (pgd_page_vaddr(*pgd_k) == (unsigned long)lm_alias(kasan_early_shadow_pmd)) {
+			p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
+			set_pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
 		}
-		vaddr += PAGE_SIZE;
-	}
+	} while (pgd_k++, vaddr = next, vaddr != end);
+}
+
+static void __init kasan_shallow_populate(void *start, void *end)
+{
+	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
+	unsigned long vend = PAGE_ALIGN((unsigned long)end);
+
+	kasan_shallow_populate_pgd(vaddr, vend);
+
+	local_flush_tlb_all();
 }
 
 void __init kasan_init(void)
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210226180154.31533-1-alex%40ghiti.fr.
