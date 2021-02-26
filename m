Return-Path: <kasan-dev+bncBC447XVYUEMRBTHB4OAQMGQE2Y6FSWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C20E3262FF
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 13:59:56 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id y3sf3922490ejj.20
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 04:59:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614344396; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZTmREIRuXVZwOrYqSoyKrr8qmTDN3nsN+qIEjzWI4B3VEFTmfYgib6SijcjldKiAaY
         vqwlse76iUsaytvo7b8itNi9Q0oWRd+ENnXsPama+BexhByQqeTWys8xrM8kV/+5eyzt
         7f62HSlkesJNbZzQhzx8mttmdnA37RZFzngYnzGBVtxzvWkRutv/m2G7e7LHEhRdy1Xz
         7BNd6ZK5rroVz9eW/ZiM58qhP96iiktVWRwfHIDStwa6CsslqOvM6+AYdJulis87BPJG
         MVUwymX9voiqdU35tKaiQsuhShS6z7Due/KQyDwuwXOSADYcvCIPKkTZatJS5noUxxSg
         r/RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=7VPLBv/npIszxSqqRXcHdqQAIq91X7XdcnJKg5pRev0=;
        b=RHPK5oBAI6Df2b2tBbHBUdM9ymroeyWUvzw1eUdxBqzr3TeN4eKUrOvinN0NGWWxZf
         u0q4HowN/sW+GInuPV77qXGNuG99MnzekeosW4PGMCMpy52Arz9ZoiKFCXDaxoevDMJ5
         LDEG6M/n4m1F4ail2MhRyh8Xm6zYZoVsl6Ecbb3ox5qJ5tLqZuvYH4QvTFgRkVKhjJIT
         9i9iVYayUSJkGQbpd6Lg8irlAisVRv4R75eyRrILbKwabaY721gZLz2ozNGeZsDY63nM
         9JFfOp1PYiVI0+yA6OILLcsAg3JRAudV0vGTPuUZBjp2QLty8wk3y0ufEeFCu7rhoSLh
         0OOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7VPLBv/npIszxSqqRXcHdqQAIq91X7XdcnJKg5pRev0=;
        b=Ep32XvK6UbdUblGuZF8/yqPxAej+juVvbXhkrh3BhQ1hOllfD7zzNIZuK96I0ibOPU
         0oRKEdzc3g4KAi7ICl539lr/AQM9hgvE/B53lnSiKlI14FSDUx8ZUBpd+WD1IqKnH20U
         vGAo5W+h6Ybko21mc8v0pus0hMkOXHyIjc86ficc0cRj/7IGTi62XzcjRg9gnB2aS+s1
         G/Y9u1yIHTOH7aiipe24iVw5NKl+thmwepKY5MXxy4dEwKK7jFtrj8JAWeZogHAuhaUV
         pRtAHgcIwR6BYQAP1S+cVPR0ed6FucI/SzRmSPZf3sKq0I50oALvilt7EnCwX4hMGTZk
         Slxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7VPLBv/npIszxSqqRXcHdqQAIq91X7XdcnJKg5pRev0=;
        b=a9t56vA46qcyJP750ExC7I87asBuP8tabciAo2y5n5ZvP/K8ohX90H7I/VYy5S/3iu
         phlw68X64TcxWhJGTupWX/uv54j83xYSLl3w69vVGD54pP4gq38KQBRpKRmGhOOAdb1G
         lSCpt8919gjg064aJY0OCeUJ31IcxuSuqzhowvykXgj+FZmYlEuHxNbCpFvdHIxhqcfS
         3q9HV4EXL5Byh+L+RJjZE6HFnupkvIZS7HGJPpN/yICsbJP3sDSmy6m044abh4m4Bs9k
         Ln0z+TDQAl9bhg7msNYQ9QM4Pve0OhtTwLNRpj4KCWeJSpc7KPCyx8TTFG10hXGLbwAe
         +rvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530S5yxwb2xjXwVKMybpGpsqVcU1t5rCw8EpNnW4HBdkJSfeCU6I
	mswez0eUL/lX6Q56nTf02fg=
X-Google-Smtp-Source: ABdhPJz1d5zEsWbO6XwJrtMm3y9LKWUbY96H198TU0G9KBDhBPZ5Gb2+zVKS07SFXCCqkqczeknnrA==
X-Received: by 2002:aa7:cd8d:: with SMTP id x13mr3122146edv.286.1614344396361;
        Fri, 26 Feb 2021 04:59:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:520e:: with SMTP id s14ls4670237edd.3.gmail; Fri,
 26 Feb 2021 04:59:55 -0800 (PST)
X-Received: by 2002:aa7:c345:: with SMTP id j5mr454456edr.338.1614344395524;
        Fri, 26 Feb 2021 04:59:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614344395; cv=none;
        d=google.com; s=arc-20160816;
        b=CvuMa9Z6aKUBdflANuu0FYHFcgtuzmc8n6ttYsS0eegRXQYYT9xROs1NXaVNDVJKtv
         TrakvdndZHM9AFRtpJ/KPLnS3UXKmWg2h4+C0iqx7wDjMYKDkcJEZj+jfHBUA2SxFzjI
         yY20XSype9Ml3+s8S48GeZD6vKvZKi9ZceTqSqOC+8h2wrYEMyYy6dt89qTcLfRVOdSh
         HP5vWbVvb1gAV4dBbHvjNfHA5x3BWbep80jnPCnXnDgTO9BFzXHurkvpULqZ//HIUvx7
         LvkzRzA6r8FAknRFqu7kfplseuwqv8Xn30+WMyUHLy7WXVZ1e0Le5J/oQ2fpTRp4QBTs
         pt4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=8iVx5TJSSQURCcQ3/XV/bgWPeBBQOqz0YJzvijvskzU=;
        b=Xs5BJ75mTKBN0J1ZTYRlbGPFh9NVgfUX+3oVADZ/Ck88kpyC4pzpjN3+Bd9EKX0WJz
         wP8zQd0quriTsmJV+OV8mnTFc0ViQII6xEJF0gsyJRZjd9/EuT81ACOJC83mA5PdRNc1
         KqL5xzUllV+jRIQJXCHybFnHG8BvuKtPDWHBsDdcAttk8nDcbdfsR2PHP5jVlx6rpJdo
         Vq4BgZum0DS926yYwNtzFZ5tdUXbLx8OIdU6kHonAXjvxaks3CJYbO+y+rTSQH8ijy6c
         lIvm9zu51kJfZoEnA0bkK36WevBbsYmKtekO8NES9A+U4bk27fLNEpvkLQtbOI2XbEWc
         BY0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay5-d.mail.gandi.net (relay5-d.mail.gandi.net. [217.70.183.197])
        by gmr-mx.google.com with ESMTPS id t7si37854edr.0.2021.02.26.04.59.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 26 Feb 2021 04:59:55 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.197;
X-Originating-IP: 81.185.174.212
Received: from localhost.localdomain (212.174.185.81.rev.sfr.net [81.185.174.212])
	(Authenticated sender: alex@ghiti.fr)
	by relay5-d.mail.gandi.net (Postfix) with ESMTPSA id 4FAAF1C000A;
	Fri, 26 Feb 2021 12:59:49 +0000 (UTC)
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
Subject: [PATCH] riscv: Improve KASAN_VMALLOC support
Date: Fri, 26 Feb 2021 07:59:33 -0500
Message-Id: <20210226125933.32023-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.197 is neither permitted nor denied by best guess
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
 arch/riscv/mm/kasan_init.c | 59 ++++++++++++--------------------------
 1 file changed, 19 insertions(+), 40 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index e3d91f334b57..b0cee8d35938 100644
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
 
+void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned long end)
+{
+	unsigned long next;
+	void *p;
+	pgd_t *pgd_k = pgd_offset_k(vaddr);
+
+	do {
+		next = pgd_addr_end(vaddr, end);
+		if (pgd_page_vaddr(*pgd_k) == (unsigned long)lm_alias(kasan_early_shadow_pmd)) {
+			p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
+			set_pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
+		}
+	} while (pgd_k++, vaddr = next, vaddr != end);
+}
+
 void __init kasan_shallow_populate(void *start, void *end)
 {
 	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
 	unsigned long vend = PAGE_ALIGN((unsigned long)end);
-	unsigned long pfn;
-	int index;
-	void *p;
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
-		}
-		vaddr += PAGE_SIZE;
-	}
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210226125933.32023-1-alex%40ghiti.fr.
