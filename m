Return-Path: <kasan-dev+bncBC447XVYUEMRBG7YWGBAMGQEWS7VYAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A1DB339D18
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 09:47:24 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id r79sf8815026lff.20
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 00:47:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615625244; cv=pass;
        d=google.com; s=arc-20160816;
        b=RU2ZrS6wUid9fajmwWqlfmZYwK9xqcwqOryUnn75FnwHZL5OPAn8ucW+a6WdrhJzf2
         TXnnUjTlmefe2A+rXq8wh3VM2vG53jtUzvrpKo08ePBJAvDcBF0lL0M680ryvkCMYaBq
         M0asXQs163pMq/m3SiBvvgusVeiYVPVJO+7LivDy/+1qpMuvXUWEnklFZGhOSBl+R+Uw
         C+c9bpW81csTiEpqHedEiMc0PqQMse0Sb4OWYi2LaYQmlb4wEUeFoTrczO2xqcyhdi2k
         4kLynV4Gb+PTbpRDZgOtwhoFLdPbEGqc1Kn88oDq7QYOOeSotw+/CtgRGZK6z+htlWWc
         JxTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gh0rOiwwnFaBLMYI/NKi2LJHzCP7tytgsPaVGQlcQtM=;
        b=oynDZUbhEqFroVM0U20F91hSxr2W3Y3f4ngECmR2tL0T8L793RneLsQRbYOpx/Udjv
         RVeItm6L7D7/vAMNARICNkI3IfOFbT9gGv5FVAtwJ9kPI3wwAy9aTwg9K7UFhGQGP8nC
         vR/MOl4/esmYv8LuWDfAtky+oDVWf97A3le+Cfx6zOae5gkyqz1BLZn0kTHN2TKUx/qu
         cAPTtyGUXkVmf86vZms104ARTw4Uy8WR5aFkFVLs8b49+SFdWzBmUpmhvUSti3F5QHUJ
         VYtwW41bL2GxzwyQGzLZV0eyUeZCctFbCyY8Jr4yc/31a69tuSM6NAj51WTriZ81VKj/
         YikA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gh0rOiwwnFaBLMYI/NKi2LJHzCP7tytgsPaVGQlcQtM=;
        b=Wb0oqI2JgiL2sQ06QTx8d0TjxInBAa9lRYjILwhJdmRXkVAgDGIF9kEd4e9WdkDIWU
         5L1e1oTDPabN1AbHM++Mp14ZZriOhGpCiq9y9L0bn3Ywakrn5b85oKBaHWB9vQINW3S9
         XSy50gs6vbVsec2tcUMRSNY7fe8trzqOC6B8KZt30PxOAyU+lql1L200o+PX6MHuYa8w
         912k+2p+0tzUsXEQAYhn84/IRaFEkdUHh+iabbwTpjrwUaEDulG1j9+0CvnD3OcZAUih
         JFdVbOkmUKve0oog/eH9cOBA9C8KNu3ET6L2fTx0br3vDqfTFhuqogwpqKctUkXl4Xsj
         cmkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gh0rOiwwnFaBLMYI/NKi2LJHzCP7tytgsPaVGQlcQtM=;
        b=K0cup2O8owhf21zwohsau3d0DK42G6dSLpf2X1jFI6mgr+RyVJLPGDrnl2Jus024ou
         m9Oqgfosdls5i+mu5nJr7XwLpddh/SwLOEdXRkS2XQ62WWtUFeK6EbKH3Cwzo+VuwFck
         +2pPiU0+KQ4cEELsJMdl3eabGmt5vsXQlKWnmnvul6/QoDzugFBZHAaQM4kr9MY1MruD
         3XAa/FLMG10Twgkk/YfsKLnCx+fyyGSWJWDGu4XSRKx5e4RsnISqTSywBvzKQeZQ8Zo7
         pEVm8v7xvt3BODX1VttSLjpwfyg7Dbh0lOhCUzDT7TqbfDDNPFerG6stNe3QVVmwH+NU
         DAxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532MSVJotSuNbfs11yia/5hUsdmWVXmV+qn36z9LllcdkCvqmd4d
	YUT0qrNIp3J2pGEhkSszgq4=
X-Google-Smtp-Source: ABdhPJwtfcxk+bIUN5VH8Napy842S1eCv68jkLSnoYOkzuvgmkGBwl85wntXf+I7rzNsE/BugynW7g==
X-Received: by 2002:a05:6512:3a93:: with SMTP id q19mr2083729lfu.186.1615625244174;
        Sat, 13 Mar 2021 00:47:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8503:: with SMTP id j3ls2446504lji.6.gmail; Sat, 13 Mar
 2021 00:47:23 -0800 (PST)
X-Received: by 2002:a2e:8ec1:: with SMTP id e1mr4750019ljl.236.1615625243202;
        Sat, 13 Mar 2021 00:47:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615625243; cv=none;
        d=google.com; s=arc-20160816;
        b=AUcD1SJXuR6BIDegyrNT9D/r2KHeRwRRsiknl2pmH8Pysev/mwEXV6ks7/mPO4VMlK
         e/rqc6gPuHKyKENiAkdN1l/of1zI5RO/uh/R1vdzKZ1tYqnbxZsGustThP6Ie0qex3ga
         urxDrwLN7J5x13yJYy7HdDriW13unVDz21b0aAhlx4blSF7IhHq83H9sujeyKGoRbM2O
         blSAkOAbDldB+u71wXA/VWbsdBymYCcjjy2jhzLod3grHX594hokik9qUdMvjMHfdp1Q
         ePGexbTZ+9pLbs2CA3sCAQwIaeF26jq4f1JQPm6bgyXdLHREONzI/p7zWoS5ku5l/Um5
         IJfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=yPH/fKQdSxAk5DApW7/ZCJv2edu7ddtmOfCKfuC+8UM=;
        b=mpX0mEMQcXPTsQTXiIziDK+de9ud9ukyJzEgqUJQ6JLZpVzneBlwacs03gbjwnMii1
         8+LeUIPEXvBINZHLrOoZ0GEhpt774sVW9ndk4/DxdDLTQaw+najdq72DyLP09yWAR3Dq
         zufjywg50t00gNH0q/2HNSXwAqo1kzIBrpDUuzonMMgyVMmJUQA8/ln436MkcRGN03sV
         5jQYrCQ1O8BBkpZ4h5EdVGL2dZxMgFc7qgN7Q0ZyXSViB5jcOLMs2JfOp7IgN6rnXoGP
         s/5uB5y38SMVKwvtP4YJLHOvGm7S+rF8R796FPwr0xZMzj6rbfzxLpyDINXLqEGalvG4
         2brw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay12.mail.gandi.net (relay12.mail.gandi.net. [217.70.178.232])
        by gmr-mx.google.com with ESMTPS id m17si245463lfg.0.2021.03.13.00.47.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 13 Mar 2021 00:47:23 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.232;
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay12.mail.gandi.net (Postfix) with ESMTPSA id A4B27200005;
	Sat, 13 Mar 2021 08:47:19 +0000 (UTC)
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
Cc: Alexandre Ghiti <alex@ghiti.fr>,
	Palmer Dabbelt <palmerdabbelt@google.com>
Subject: [PATCH v3 2/2] riscv: Cleanup KASAN_VMALLOC support
Date: Sat, 13 Mar 2021 03:45:05 -0500
Message-Id: <20210313084505.16132-3-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210313084505.16132-1-alex@ghiti.fr>
References: <20210313084505.16132-1-alex@ghiti.fr>
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.232 is neither permitted nor denied by best guess
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

Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
Reviewed-by: Palmer Dabbelt <palmerdabbelt@google.com>
---
 arch/riscv/mm/kasan_init.c | 59 ++++++++++++--------------------------
 1 file changed, 18 insertions(+), 41 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 57bf4ae09361..c16178918239 100644
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
@@ -155,38 +143,27 @@ static void __init kasan_populate(void *start, void *end)
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
 
 	local_flush_tlb_all();
 }
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210313084505.16132-3-alex%40ghiti.fr.
