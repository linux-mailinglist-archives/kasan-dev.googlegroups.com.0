Return-Path: <kasan-dev+bncBDXY7I6V6AMRB3F2XGPAMGQEC2TXCCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id BE4DF6778C1
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:11:57 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id k20-20020a05600c1c9400b003db2e916b3asf5791208wms.6
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:11:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674468717; cv=pass;
        d=google.com; s=arc-20160816;
        b=RbsSMA0liCWkHlwBMyHSwGucb2KHwZGwUj3QaHEDGRciRYiOYaoySHnW1vlWCLIpqi
         Z1aVmyNu5nwT6M1tvM8az/VG0289/yUKHt0WuS3HRYXP/73cL0leJAfwuP0wOof5JJNL
         URp6XW+gUgclRDRisWjYNamhTXQwdK4H2OBhb/krm66KdsgYageRou8sF2x8Xib6H5fv
         H3JgK5YTDt3xb5HyL4UYIk9eL1p9k9e4rfF5YSVJBDkVDZTpFg7Z6JxSXcAjTC39Ebzk
         KYEAtDcz9GhGIsM5FECk7GszXngwQBNCp8Mrfvvcx66GO4bXG9JgVAPsAmVLgPpy5dSU
         V1DQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8wcfsUOp1TxeKpuagUQlbr7GbT0oRFBMlDvAADpNV+U=;
        b=ZC+8VHDEkBvbgle+KMTsh9ox8t/rogvP9h4T58YjC95QFTn54EkuCFuMYYiHIzbnDQ
         LqnCei5a7NwkPY3xu2WfssAdgwJXHc/N0PL2lRP+Ko/We62BtXIWm8pf8E3nDHP7Rkdx
         RKgrZ4wfw5lqVIJwF7JE0iYUsAVrk5+rCzkTIq+vGmn/iwQeo3hXoSdiIkCbQbPqyggs
         RDKZHue7hTHMMa1EolG4o+1HShf1OdqFk63i+Q+0JZZIm6YTbT9ufYbL5Qq0aJpY+Dg6
         Z0lt9AOk4nDkjX+wTUAF/BEosOubguB9tYgcv7ZlKSjS8Ko7Mr6ZMUwG0U7O2XlBNXc3
         6GJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=Px8HOMIW;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8wcfsUOp1TxeKpuagUQlbr7GbT0oRFBMlDvAADpNV+U=;
        b=RIUWgp0SAaMSSojjpylZRAVwxtRGqO4AC1XoqA5Cvbs5VOCHhXXocNG/sRJ7t+U5Zb
         PVpOt4wDR3Rebsrx2JBQv7FFeCm3yTzu3JHEijy6uMzdWIObe0mkUXNe903szA4ZvUAm
         /TYHi/WorTxQeCduw+vdAkoRJ17/ean2nX6ShnXzpvM251SCH9mJeaGKmq42GDQcmzLB
         CMVWQ9mHUSRHg4gTo2J3YrgCMosmj5qr7YD4La+tJo6q1uTWx4QNiijk2dU6fhsIRgru
         zv/NmjqdXgT9aWI87cIrHXbrmAUYnAGgWKHnggNY8Mjd7ZuJEqY4ckM6pT662r0OsX9y
         KS6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8wcfsUOp1TxeKpuagUQlbr7GbT0oRFBMlDvAADpNV+U=;
        b=WmDSLOZRIih+4CAt1agneE0/r6rMg3DMEgPR/33T+Is4Tl/ojcthoaVmMTOQEng/AV
         lSctP6ICapdnU/VDbkN6vbiIN9ivIT3b1usPLAANIeRvAka3yLrHUPOFIndewWdRVOJj
         ygZ18G8s6SCWBGA90LitNSP5jgqKQx+fc8KxDsXncN0ivIN2etxNT6JkDx7Z6IO4n8dE
         7PPvnbwUWpVE/FuPkz/m9TnOiAjexPInwKxJU9sJ8enZJfKaiNDvI2XllswavcT6Rwoz
         es4dgXrhWZ8kFaX6knc7KqjgK4iojIIkcb5GL1LZFo6gZNEmdaKI+XRLGnXmoWD3qRnH
         d+3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kolypzXyXpjVjqbfphIf7rgEcQANzs3LErACeDWJfCZDSK4o3ln
	XYIDb7vwzPXW4r+fCMH3xng=
X-Google-Smtp-Source: AMrXdXuolNkq68wm+UgTJL4wsxEAeAoiknu85W0XxcqAh2de1YPEDFR/fpBZBGKXCeUFMmghxtdU4Q==
X-Received: by 2002:a05:6000:183:b0:2bc:3d:4734 with SMTP id p3-20020a056000018300b002bc003d4734mr866259wrx.274.1674468717112;
        Mon, 23 Jan 2023 02:11:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b90:b0:3d1:be63:3b63 with SMTP id
 n16-20020a05600c3b9000b003d1be633b63ls7888730wms.1.-pod-canary-gmail; Mon, 23
 Jan 2023 02:11:56 -0800 (PST)
X-Received: by 2002:a05:600c:4928:b0:3d3:4aa6:4fe6 with SMTP id f40-20020a05600c492800b003d34aa64fe6mr23577510wmp.3.1674468716001;
        Mon, 23 Jan 2023 02:11:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674468715; cv=none;
        d=google.com; s=arc-20160816;
        b=roGw7RXGXeKvVzewZDODmU5zzdNpCSvdxq+k52/+yFVed0Bpfd9i6TEKXWXCV414jS
         dDk+ocAyDc5eixyhP3CGpxWOFbCXv9ORsmDZ1qbOgxFVTtvUJIPgKR/BpAdwx/E7+VwG
         Yi8SLCUAzPGvLTuOaCgP5xCRWQIyijh3xhU2/jN4kO5943eSAfovMre3J37YK8QP95cF
         TDAaKL9OBMe0L31Iz90kceFzPv/+RDrSQQSYUGyBm1fsq/Jb9KQ6ESuuvtGE3CtMuoIt
         9HdYqtOkuKhpn1rnpuTQFtMSXXRlasMLkJwVnkabt4aYtxOXk8eXc+s06gdpg6ske2FW
         mKpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QbEdbwlNHes0ugCmE+3zBdA4gzYQZSnhOGb2z28HEZQ=;
        b=UarDnm0SBMZnfk6+ufiKBY1GABOzLjgGRvN47jOA3Uk4lb3Lya3xyiVxaOP9a+eNU2
         uaYHSF2V59ZeBHmH7r9tWU9nmakaZPF6//EKXuzpAxVA4UoxF8a43XaNYdEUC8PZbOqC
         4AZ4UHGy8xWrQ7E9CLrQsbvVCQ7xC+JfPAYfmAlbGKEV3ZEdErot3S8tcDKKK2/5+74C
         mnU2np9NbJPMAZKDNtPG3DwUAC0sJP0E6FEBg/2vk8QNqT+npzflciTzTdbpcgfzwLs/
         seUrYpZm5jmAJTIUlTxTaVBuBBxYEUSPTp/ONlrTT1epAVmQkQTihsu0nFYL+p8G4AhL
         rkmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=Px8HOMIW;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id o10-20020a1c750a000000b003d9ae6cfd2esi480122wmc.2.2023.01.23.02.11.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:11:55 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id m5-20020a05600c4f4500b003db03b2559eso8113636wmq.5
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:11:55 -0800 (PST)
X-Received: by 2002:a05:600c:539b:b0:3d9:f836:3728 with SMTP id hg27-20020a05600c539b00b003d9f8363728mr23608507wmb.11.1674468715691;
        Mon, 23 Jan 2023 02:11:55 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id o21-20020a05600c4fd500b003c6f8d30e40sm11335771wmq.31.2023.01.23.02.11.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Jan 2023 02:11:55 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v2 2/6] riscv: Rework kasan population functions
Date: Mon, 23 Jan 2023 11:09:47 +0100
Message-Id: <20230123100951.810807-3-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230123100951.810807-1-alexghiti@rivosinc.com>
References: <20230123100951.810807-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=Px8HOMIW;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Our previous kasan population implementation used to have the final kasan
shadow region mapped with kasan_early_shadow_page, because we did not clean
the early mapping and then we had to populate the kasan region "in-place"
which made the code cumbersome.

So now we clear the early mapping, establish a temporary mapping while we
populate the kasan shadow region with just the kernel regions that will
be used.

This new version uses the "generic" way of going through a page table
that may be folded at runtime (avoid the XXX_next macros).

It was tested with outline instrumentation on an Ubuntu kernel
configuration successfully.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/mm/kasan_init.c | 363 +++++++++++++++++++------------------
 1 file changed, 184 insertions(+), 179 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 9a5211ca8368..5c7b1d07faf2 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -18,58 +18,48 @@
  * For sv39, the region is aligned on PGDIR_SIZE so we only need to populate
  * the page global directory with kasan_early_shadow_pmd.
  *
- * For sv48 and sv57, the region is not aligned on PGDIR_SIZE so the mapping
- * must be divided as follows:
- * - the first PGD entry, although incomplete, is populated with
- *   kasan_early_shadow_pud/p4d
- * - the PGD entries in the middle are populated with kasan_early_shadow_pud/p4d
- * - the last PGD entry is shared with the kernel mapping so populated at the
- *   lower levels pud/p4d
- *
- * In addition, when shallow populating a kasan region (for example vmalloc),
- * this region may also not be aligned on PGDIR size, so we must go down to the
- * pud level too.
+ * For sv48 and sv57, the region start is aligned on PGDIR_SIZE whereas the end
+ * region is not and then we have to go down to the PUD level.
  */
 
 extern pgd_t early_pg_dir[PTRS_PER_PGD];
+pgd_t tmp_pg_dir[PTRS_PER_PGD] __page_aligned_bss;
+p4d_t tmp_p4d[PTRS_PER_P4D] __page_aligned_bss;
+pud_t tmp_pud[PTRS_PER_PUD] __page_aligned_bss;
 
 static void __init kasan_populate_pte(pmd_t *pmd, unsigned long vaddr, unsigned long end)
 {
 	phys_addr_t phys_addr;
-	pte_t *ptep, *base_pte;
+	pte_t *ptep, *p;
 
-	if (pmd_none(*pmd))
-		base_pte = memblock_alloc(PTRS_PER_PTE * sizeof(pte_t), PAGE_SIZE);
-	else
-		base_pte = (pte_t *)pmd_page_vaddr(*pmd);
+	if (pmd_none(*pmd)) {
+		p = memblock_alloc(PTRS_PER_PTE * sizeof(pte_t), PAGE_SIZE);
+		set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(p)), PAGE_TABLE));
+	}
 
-	ptep = base_pte + pte_index(vaddr);
+	ptep = pte_offset_kernel(pmd, vaddr);
 
 	do {
 		if (pte_none(*ptep)) {
 			phys_addr = memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
 			set_pte(ptep, pfn_pte(PFN_DOWN(phys_addr), PAGE_KERNEL));
+			memset(__va(phys_addr), KASAN_SHADOW_INIT, PAGE_SIZE);
 		}
 	} while (ptep++, vaddr += PAGE_SIZE, vaddr != end);
-
-	set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(base_pte)), PAGE_TABLE));
 }
 
 static void __init kasan_populate_pmd(pud_t *pud, unsigned long vaddr, unsigned long end)
 {
 	phys_addr_t phys_addr;
-	pmd_t *pmdp, *base_pmd;
+	pmd_t *pmdp, *p;
 	unsigned long next;
 
 	if (pud_none(*pud)) {
-		base_pmd = memblock_alloc(PTRS_PER_PMD * sizeof(pmd_t), PAGE_SIZE);
-	} else {
-		base_pmd = (pmd_t *)pud_pgtable(*pud);
-		if (base_pmd == lm_alias(kasan_early_shadow_pmd))
-			base_pmd = memblock_alloc(PTRS_PER_PMD * sizeof(pmd_t), PAGE_SIZE);
+		p = memblock_alloc(PTRS_PER_PMD * sizeof(pmd_t), PAGE_SIZE);
+		set_pud(pud, pfn_pud(PFN_DOWN(__pa(p)), PAGE_TABLE));
 	}
 
-	pmdp = base_pmd + pmd_index(vaddr);
+	pmdp = pmd_offset(pud, vaddr);
 
 	do {
 		next = pmd_addr_end(vaddr, end);
@@ -78,43 +68,28 @@ static void __init kasan_populate_pmd(pud_t *pud, unsigned long vaddr, unsigned
 			phys_addr = memblock_phys_alloc(PMD_SIZE, PMD_SIZE);
 			if (phys_addr) {
 				set_pmd(pmdp, pfn_pmd(PFN_DOWN(phys_addr), PAGE_KERNEL));
+				memset(__va(phys_addr), KASAN_SHADOW_INIT, PMD_SIZE);
 				continue;
 			}
 		}
 
 		kasan_populate_pte(pmdp, vaddr, next);
 	} while (pmdp++, vaddr = next, vaddr != end);
-
-	/*
-	 * Wait for the whole PGD to be populated before setting the PGD in
-	 * the page table, otherwise, if we did set the PGD before populating
-	 * it entirely, memblock could allocate a page at a physical address
-	 * where KASAN is not populated yet and then we'd get a page fault.
-	 */
-	set_pud(pud, pfn_pud(PFN_DOWN(__pa(base_pmd)), PAGE_TABLE));
 }
 
-static void __init kasan_populate_pud(pgd_t *pgd,
+static void __init kasan_populate_pud(p4d_t *p4d,
 				      unsigned long vaddr, unsigned long end)
 {
 	phys_addr_t phys_addr;
-	pud_t *pudp, *base_pud;
+	pud_t *pudp, *p;
 	unsigned long next;
 
-	if (pgd_none(*pgd)) {
-		base_pud = memblock_alloc(PTRS_PER_PUD * sizeof(pud_t), PAGE_SIZE);
-		memcpy(base_pud, (void *)kasan_early_shadow_pud,
-			sizeof(pud_t) * PTRS_PER_PUD);
-	} else {
-		base_pud = (pud_t *)pgd_page_vaddr(*pgd);
-		if (base_pud == lm_alias(kasan_early_shadow_pud)) {
-			base_pud = memblock_alloc(PTRS_PER_PUD * sizeof(pud_t), PAGE_SIZE);
-			memcpy(base_pud, (void *)kasan_early_shadow_pud,
-			       sizeof(pud_t) * PTRS_PER_PUD);
-		}
+	if (p4d_none(*p4d)) {
+		p = memblock_alloc(PTRS_PER_PUD * sizeof(pud_t), PAGE_SIZE);
+		set_p4d(p4d, pfn_p4d(PFN_DOWN(__pa(p)), PAGE_TABLE));
 	}
 
-	pudp = base_pud + pud_index(vaddr);
+	pudp = pud_offset(p4d, vaddr);
 
 	do {
 		next = pud_addr_end(vaddr, end);
@@ -123,37 +98,28 @@ static void __init kasan_populate_pud(pgd_t *pgd,
 			phys_addr = memblock_phys_alloc(PUD_SIZE, PUD_SIZE);
 			if (phys_addr) {
 				set_pud(pudp, pfn_pud(PFN_DOWN(phys_addr), PAGE_KERNEL));
+				memset(__va(phys_addr), KASAN_SHADOW_INIT, PUD_SIZE);
 				continue;
 			}
 		}
 
 		kasan_populate_pmd(pudp, vaddr, next);
 	} while (pudp++, vaddr = next, vaddr != end);
-
-	/*
-	 * Wait for the whole PGD to be populated before setting the PGD in
-	 * the page table, otherwise, if we did set the PGD before populating
-	 * it entirely, memblock could allocate a page at a physical address
-	 * where KASAN is not populated yet and then we'd get a page fault.
-	 */
-	set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_pud)), PAGE_TABLE));
 }
 
 static void __init kasan_populate_p4d(pgd_t *pgd,
 				      unsigned long vaddr, unsigned long end)
 {
 	phys_addr_t phys_addr;
-	p4d_t *p4dp, *base_p4d;
+	p4d_t *p4dp, *p;
 	unsigned long next;
 
-	base_p4d = (p4d_t *)pgd_page_vaddr(*pgd);
-	if (base_p4d == lm_alias(kasan_early_shadow_p4d)) {
-		base_p4d = memblock_alloc(PTRS_PER_PUD * sizeof(p4d_t), PAGE_SIZE);
-        memcpy(base_p4d, (void *)kasan_early_shadow_p4d,
-                sizeof(p4d_t) * PTRS_PER_P4D);
-    }
+	if (pgd_none(*pgd)) {
+		p = memblock_alloc(PTRS_PER_P4D * sizeof(p4d_t), PAGE_SIZE);
+		set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
+	}
 
-	p4dp = base_p4d + p4d_index(vaddr);
+	p4dp = p4d_offset(pgd, vaddr);
 
 	do {
 		next = p4d_addr_end(vaddr, end);
@@ -162,34 +128,15 @@ static void __init kasan_populate_p4d(pgd_t *pgd,
 			phys_addr = memblock_phys_alloc(P4D_SIZE, P4D_SIZE);
 			if (phys_addr) {
 				set_p4d(p4dp, pfn_p4d(PFN_DOWN(phys_addr), PAGE_KERNEL));
+				memset(__va(phys_addr), KASAN_SHADOW_INIT, P4D_SIZE);
 				continue;
 			}
 		}
 
-		kasan_populate_pud((pgd_t *)p4dp, vaddr, next);
+		kasan_populate_pud(p4dp, vaddr, next);
 	} while (p4dp++, vaddr = next, vaddr != end);
-
-	/*
-	 * Wait for the whole P4D to be populated before setting the P4D in
-	 * the page table, otherwise, if we did set the P4D before populating
-	 * it entirely, memblock could allocate a page at a physical address
-	 * where KASAN is not populated yet and then we'd get a page fault.
-	 */
-	set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_p4d)), PAGE_TABLE));
 }
 
-#define kasan_early_shadow_pgd_next			(pgtable_l5_enabled ?	\
-				(uintptr_t)kasan_early_shadow_p4d :		\
-							(pgtable_l4_enabled ?	\
-				(uintptr_t)kasan_early_shadow_pud :		\
-				(uintptr_t)kasan_early_shadow_pmd))
-#define kasan_populate_pgd_next(pgdp, vaddr, next)				\
-		(pgtable_l5_enabled ?						\
-		kasan_populate_p4d(pgdp, vaddr, next) :				\
-		(pgtable_l4_enabled ?						\
-			kasan_populate_pud(pgdp, vaddr, next) :			\
-			kasan_populate_pmd((pud_t *)pgdp, vaddr, next)))
-
 static void __init kasan_populate_pgd(pgd_t *pgdp,
 				      unsigned long vaddr, unsigned long end)
 {
@@ -199,25 +146,86 @@ static void __init kasan_populate_pgd(pgd_t *pgdp,
 	do {
 		next = pgd_addr_end(vaddr, end);
 
-		if (IS_ALIGNED(vaddr, PGDIR_SIZE) && (next - vaddr) >= PGDIR_SIZE) {
-			if (pgd_page_vaddr(*pgdp) ==
-				   (unsigned long)lm_alias(kasan_early_shadow_pgd_next)) {
-				/*
-				 * pgdp can't be none since kasan_early_init
-				 * initialized all KASAN shadow region with
-				 * kasan_early_shadow_pud: if this is still the
-				 * case, that means we can try to allocate a
-				 * hugepage as a replacement.
-				 */
-				phys_addr = memblock_phys_alloc(PGDIR_SIZE, PGDIR_SIZE);
-				if (phys_addr) {
-					set_pgd(pgdp, pfn_pgd(PFN_DOWN(phys_addr), PAGE_KERNEL));
-					continue;
-				}
+		if (pgd_none(*pgdp) && IS_ALIGNED(vaddr, PGDIR_SIZE) &&
+		    (next - vaddr) >= PGDIR_SIZE) {
+			phys_addr = memblock_phys_alloc(PGDIR_SIZE, PGDIR_SIZE);
+			if (phys_addr) {
+				set_pgd(pgdp, pfn_pgd(PFN_DOWN(phys_addr), PAGE_KERNEL));
+				memset(__va(phys_addr), KASAN_SHADOW_INIT, PGDIR_SIZE);
+				continue;
 			}
 		}
 
-		kasan_populate_pgd_next(pgdp, vaddr, next);
+		kasan_populate_p4d(pgdp, vaddr, next);
+	} while (pgdp++, vaddr = next, vaddr != end);
+}
+
+static void __init kasan_early_clear_pud(p4d_t *p4dp,
+					 unsigned long vaddr, unsigned long end)
+{
+	pud_t *pudp, *base_pud;
+	unsigned long next;
+
+	if (!pgtable_l4_enabled) {
+		pudp = (pud_t *)p4dp;
+	} else {
+		base_pud = pt_ops.get_pud_virt(pfn_to_phys(_p4d_pfn(*p4dp)));
+		pudp = base_pud + pud_index(vaddr);
+	}
+
+	do {
+		next = pud_addr_end(vaddr, end);
+
+		if (IS_ALIGNED(vaddr, PUD_SIZE) && (next - vaddr) >= PUD_SIZE) {
+			pud_clear(pudp);
+			continue;
+		}
+
+		BUG();
+	} while (pudp++, vaddr = next, vaddr != end);
+}
+
+static void __init kasan_early_clear_p4d(pgd_t *pgdp,
+					 unsigned long vaddr, unsigned long end)
+{
+	p4d_t *p4dp, *base_p4d;
+	unsigned long next;
+
+	if (!pgtable_l5_enabled) {
+		p4dp = (p4d_t *)pgdp;
+	} else {
+		base_p4d = pt_ops.get_p4d_virt(pfn_to_phys(_pgd_pfn(*pgdp)));
+		p4dp = base_p4d + p4d_index(vaddr);
+	}
+
+	do {
+		next = p4d_addr_end(vaddr, end);
+
+		if (pgtable_l4_enabled && IS_ALIGNED(vaddr, P4D_SIZE) &&
+		    (next - vaddr) >= P4D_SIZE) {
+			p4d_clear(p4dp);
+			continue;
+		}
+
+		kasan_early_clear_pud(p4dp, vaddr, next);
+	} while (p4dp++, vaddr = next, vaddr != end);
+}
+
+static void __init kasan_early_clear_pgd(pgd_t *pgdp,
+					 unsigned long vaddr, unsigned long end)
+{
+	unsigned long next;
+
+	do {
+		next = pgd_addr_end(vaddr, end);
+
+		if (pgtable_l5_enabled && IS_ALIGNED(vaddr, PGDIR_SIZE) &&
+		    (next - vaddr) >= PGDIR_SIZE) {
+			pgd_clear(pgdp);
+			continue;
+		}
+
+		kasan_early_clear_p4d(pgdp, vaddr, next);
 	} while (pgdp++, vaddr = next, vaddr != end);
 }
 
@@ -362,117 +370,64 @@ static void __init kasan_populate(void *start, void *end)
 	unsigned long vend = PAGE_ALIGN((unsigned long)end);
 
 	kasan_populate_pgd(pgd_offset_k(vaddr), vaddr, vend);
-
-	local_flush_tlb_all();
-	memset(start, KASAN_SHADOW_INIT, end - start);
 }
 
-static void __init kasan_shallow_populate_pmd(pgd_t *pgdp,
+static void __init kasan_shallow_populate_pud(p4d_t *p4d,
 					      unsigned long vaddr, unsigned long end)
 {
 	unsigned long next;
-	pmd_t *pmdp, *base_pmd;
-	bool is_kasan_pte;
-
-	base_pmd = (pmd_t *)pgd_page_vaddr(*pgdp);
-	pmdp = base_pmd + pmd_index(vaddr);
-
-	do {
-		next = pmd_addr_end(vaddr, end);
-		is_kasan_pte = (pmd_pgtable(*pmdp) == lm_alias(kasan_early_shadow_pte));
-
-		if (is_kasan_pte)
-			pmd_clear(pmdp);
-	} while (pmdp++, vaddr = next, vaddr != end);
-}
-
-static void __init kasan_shallow_populate_pud(pgd_t *pgdp,
-					      unsigned long vaddr, unsigned long end)
-{
-	unsigned long next;
-	pud_t *pudp, *base_pud;
-	pmd_t *base_pmd;
-	bool is_kasan_pmd;
-
-	base_pud = (pud_t *)pgd_page_vaddr(*pgdp);
-	pudp = base_pud + pud_index(vaddr);
+	void *p;
+	pud_t *pud_k = pud_offset(p4d, vaddr);
 
 	do {
 		next = pud_addr_end(vaddr, end);
-		is_kasan_pmd = (pud_pgtable(*pudp) == lm_alias(kasan_early_shadow_pmd));
 
-		if (!is_kasan_pmd)
-			continue;
-
-		base_pmd = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
-		set_pud(pudp, pfn_pud(PFN_DOWN(__pa(base_pmd)), PAGE_TABLE));
-
-		if (IS_ALIGNED(vaddr, PUD_SIZE) && (next - vaddr) >= PUD_SIZE)
+		if (pud_none(*pud_k)) {
+			p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
+			set_pud(pud_k, pfn_pud(PFN_DOWN(__pa(p)), PAGE_TABLE));
 			continue;
+		}
 
-		memcpy(base_pmd, (void *)kasan_early_shadow_pmd, PAGE_SIZE);
-		kasan_shallow_populate_pmd((pgd_t *)pudp, vaddr, next);
-	} while (pudp++, vaddr = next, vaddr != end);
+		BUG();
+	} while (pud_k++, vaddr = next, vaddr != end);
 }
 
-static void __init kasan_shallow_populate_p4d(pgd_t *pgdp,
+static void __init kasan_shallow_populate_p4d(pgd_t *pgd,
 					      unsigned long vaddr, unsigned long end)
 {
 	unsigned long next;
-	p4d_t *p4dp, *base_p4d;
-	pud_t *base_pud;
-	bool is_kasan_pud;
-
-	base_p4d = (p4d_t *)pgd_page_vaddr(*pgdp);
-	p4dp = base_p4d + p4d_index(vaddr);
+	void *p;
+	p4d_t *p4d_k = p4d_offset(pgd, vaddr);
 
 	do {
 		next = p4d_addr_end(vaddr, end);
-		is_kasan_pud = (p4d_pgtable(*p4dp) == lm_alias(kasan_early_shadow_pud));
-
-		if (!is_kasan_pud)
-			continue;
-
-		base_pud = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
-		set_p4d(p4dp, pfn_p4d(PFN_DOWN(__pa(base_pud)), PAGE_TABLE));
 
-		if (IS_ALIGNED(vaddr, P4D_SIZE) && (next - vaddr) >= P4D_SIZE)
+		if (p4d_none(*p4d_k)) {
+			p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
+			set_p4d(p4d_k, pfn_p4d(PFN_DOWN(__pa(p)), PAGE_TABLE));
 			continue;
+		}
 
-		memcpy(base_pud, (void *)kasan_early_shadow_pud, PAGE_SIZE);
-		kasan_shallow_populate_pud((pgd_t *)p4dp, vaddr, next);
-	} while (p4dp++, vaddr = next, vaddr != end);
+		kasan_shallow_populate_pud(p4d_k, vaddr, end);
+	} while (p4d_k++, vaddr = next, vaddr != end);
 }
 
-#define kasan_shallow_populate_pgd_next(pgdp, vaddr, next)			\
-		(pgtable_l5_enabled ?						\
-		kasan_shallow_populate_p4d(pgdp, vaddr, next) :			\
-		(pgtable_l4_enabled ?						\
-		kasan_shallow_populate_pud(pgdp, vaddr, next) :			\
-		kasan_shallow_populate_pmd(pgdp, vaddr, next)))
-
 static void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned long end)
 {
 	unsigned long next;
 	void *p;
 	pgd_t *pgd_k = pgd_offset_k(vaddr);
-	bool is_kasan_pgd_next;
 
 	do {
 		next = pgd_addr_end(vaddr, end);
-		is_kasan_pgd_next = (pgd_page_vaddr(*pgd_k) ==
-				     (unsigned long)lm_alias(kasan_early_shadow_pgd_next));
 
-		if (is_kasan_pgd_next) {
+		if (pgd_none(*pgd_k)) {
 			p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
 			set_pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
-		}
-
-		if (IS_ALIGNED(vaddr, PGDIR_SIZE) && (next - vaddr) >= PGDIR_SIZE)
 			continue;
+		}
 
-		memcpy(p, (void *)kasan_early_shadow_pgd_next, PAGE_SIZE);
-		kasan_shallow_populate_pgd_next(pgd_k, vaddr, next);
+		kasan_shallow_populate_p4d(pgd_k, vaddr, next);
 	} while (pgd_k++, vaddr = next, vaddr != end);
 }
 
@@ -482,7 +437,37 @@ static void __init kasan_shallow_populate(void *start, void *end)
 	unsigned long vend = PAGE_ALIGN((unsigned long)end);
 
 	kasan_shallow_populate_pgd(vaddr, vend);
-	local_flush_tlb_all();
+}
+
+void create_tmp_mapping(void)
+{
+	void *ptr;
+	p4d_t *base_p4d;
+
+	/*
+	 * We need to clean the early mapping: this is hard to achieve "in-place",
+	 * so install a temporary mapping like arm64 and x86 do.
+	 */
+	memcpy(tmp_pg_dir, swapper_pg_dir, sizeof(pgd_t) * PTRS_PER_PGD);
+
+	/* Copy the last p4d since it is shared with the kernel mapping. */
+	if (pgtable_l5_enabled) {
+		ptr = (p4d_t *)pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_END));
+		memcpy(tmp_p4d, ptr, sizeof(p4d_t) * PTRS_PER_P4D);
+		set_pgd(&tmp_pg_dir[pgd_index(KASAN_SHADOW_END)],
+			pfn_pgd(PFN_DOWN(__pa(tmp_p4d)), PAGE_TABLE));
+		base_p4d = tmp_p4d;
+	} else {
+		base_p4d = (p4d_t *)tmp_pg_dir;
+	}
+
+	/* Copy the last pud since it is shared with the kernel mapping. */
+	if (pgtable_l4_enabled) {
+		ptr = (pud_t *)p4d_page_vaddr(*(base_p4d + p4d_index(KASAN_SHADOW_END)));
+		memcpy(tmp_pud, ptr, sizeof(pud_t) * PTRS_PER_PUD);
+		set_p4d(&base_p4d[p4d_index(KASAN_SHADOW_END)],
+			pfn_p4d(PFN_DOWN(__pa(tmp_pud)), PAGE_TABLE));
+	}
 }
 
 void __init kasan_init(void)
@@ -490,10 +475,27 @@ void __init kasan_init(void)
 	phys_addr_t p_start, p_end;
 	u64 i;
 
-	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+	create_tmp_mapping();
+	csr_write(CSR_SATP, PFN_DOWN(__pa(tmp_pg_dir)) | satp_mode);
+
+	kasan_early_clear_pgd(pgd_offset_k(KASAN_SHADOW_START),
+			      KASAN_SHADOW_START, KASAN_SHADOW_END);
+
+	kasan_populate_early_shadow((void *)kasan_mem_to_shadow((void *)FIXADDR_START),
+				    (void *)kasan_mem_to_shadow((void *)VMALLOC_START));
+
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
 		kasan_shallow_populate(
 			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
 			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
+		/* Shallow populate modules and BPF which are vmalloc-allocated */
+		kasan_shallow_populate(
+			(void *)kasan_mem_to_shadow((void *)MODULES_VADDR),
+			(void *)kasan_mem_to_shadow((void *)MODULES_END));
+	} else {
+		kasan_populate_early_shadow((void *)kasan_mem_to_shadow((void *)VMALLOC_START),
+					    (void *)kasan_mem_to_shadow((void *)VMALLOC_END));
+	}
 
 	/* Populate the linear mapping */
 	for_each_mem_range(i, &p_start, &p_end) {
@@ -506,8 +508,8 @@ void __init kasan_init(void)
 		kasan_populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
 	}
 
-	/* Populate kernel, BPF, modules mapping */
-	kasan_populate(kasan_mem_to_shadow((const void *)MODULES_VADDR),
+	/* Populate kernel */
+	kasan_populate(kasan_mem_to_shadow((const void *)MODULES_END),
 		       kasan_mem_to_shadow((const void *)MODULES_VADDR + SZ_2G));
 
 	for (i = 0; i < PTRS_PER_PTE; i++)
@@ -518,4 +520,7 @@ void __init kasan_init(void)
 
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	init_task.kasan_depth = 0;
+
+	csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
+	local_flush_tlb_all();
 }
-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230123100951.810807-3-alexghiti%40rivosinc.com.
