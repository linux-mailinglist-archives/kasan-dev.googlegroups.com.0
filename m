Return-Path: <kasan-dev+bncBDXY7I6V6AMRBCWPYOPAMGQE6I5M7ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BAB967AB8B
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:25:47 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id h24-20020a05651c125800b0028b843bbf33sf3868750ljh.10
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:25:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674635146; cv=pass;
        d=google.com; s=arc-20160816;
        b=IaAJRg015jARRwdBfA25GVUM4L5hyBselnX1cruJCUYHy6URK6pvCnvq437PObN30x
         QLZ5wtqK6G6qNdwjip7igJpE+c+ZqiZWXf8RuDVRQGhkzoc4K0YKkB711bl5XrVuYKDs
         35yTb4Lo270iv/ryzH+qJUV49zWwJW35jnvbtB8KZfiO7lUzVr58fjGdbjhWOY2q+38O
         6KzH92PXQvjWJ98Km1/Tco5WzilHAumjLMJ0DGnVY27LEb+vf3Sve5k/8I69yUuEJUXW
         clFULCE6BRAJsYd04fSGPhiFUeGdts94g7Heqb3ebT/kUC33DFxQ5c3nMEQ8+Dp4pEUu
         rZnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EQ0W32dpGB9fn6l7JTrpih8mgYMA57Vrmr+QQfJ8J5w=;
        b=FIMDpwYLfw1AZvXEObVPKXsU6lrHs8xiVHqQe+4WpS3s+I1S2cNVrN4B+zv/BIt8x/
         wKB9n0OCQW9OxI299oyq5JTPiT2V9gznKJxykC0PFNzcaL+f4KEfVG8Z1uDHVx/tP2pK
         tQFR5nO0aPE0xhRbYmr6dWyk8pfTsG5hACCtKBgPreTtsSohxM/3h/Qg0XFPhkrslAlq
         orZaT+ce6Wlu3bcJoUNkoGtQvc7aELsICoWfm0rDeQBEhDNNaBxmsjTLzHP2enVQEESN
         VvovZosPPkSwQbwVROgCx/S1iRVypCAL94AMq5Ztcrte2OeqXI7Rz48d1K1qrt+4Dz5i
         yICg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=lPB1mHHn;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EQ0W32dpGB9fn6l7JTrpih8mgYMA57Vrmr+QQfJ8J5w=;
        b=ZrvI34nao8ImWOdMQW7Uxj5ynkT7Z7IozYyWCimgJ0KFFGmcuEQVUwDkQpLMqRgvJF
         LMKeP9WOJg9qeCVfEGVGcMCKCUG9rG7CuQnKEu48V+Z7YrIhG4MRw25TV3t5KhHxi5nJ
         lnaKP/UDBdQ0fVXQEwyIe/QMMDO3xQ8+o0oExoMmlVLOcwc34T3/SH1olnTOnrvPchxW
         nDOd+28uba/AQEXlbgVsyEwqhyYbkkoG3nZeYU7zo9H3mHtYTaTWA4VWYARe9Mm/GEmr
         Yp18UK2LuxfNd7BgCUc0N3CQc1yhLeAgM3xYfVUbpQgxVIElC232LV1rZXK6N0KUuYfU
         lfrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EQ0W32dpGB9fn6l7JTrpih8mgYMA57Vrmr+QQfJ8J5w=;
        b=vkXxyduhxaf9xdeUTe2mQ4DLAZ8Y8ZYjudA9LlSiTMUstcc6Nljfx0NatSRAvmgb9L
         Nzbct0cN9IvVB+KSdLFCrunvaRMpnIMQ0s1uXgrAaU/DKZp32C3oIf0zJjbTTj+E4Oy9
         3Ip44YvuABd/Vyx3+kbgHxdqaiWpuVDICNnrku7YvDE0x2M6xN3LMBHag8WCNsM8IVff
         VbAdRC5W4fiX+x+ZllcNbkz1Eqbt62kiImdn+Oe6nYoCsg9vUv4vYxcmBn3mcnyBABXH
         P3NvgdmmZ7NVYZNwWFPUk+3LRnG3p0tWRi8N+ACwE1clgg5fiIOt76AkGsDJVzgEBLFY
         9YCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2ko2cox9dpwPjCsT9or7RUU6cwAXatzX7tiCvRCeKVJLypPh0fBy
	xzk6CCtjV4QywANHCQSQnsk=
X-Google-Smtp-Source: AMrXdXu8dAuRciL4YOolp1xmtj39LXsrG3mwaSn13kApK630pfH4HMfEAIC30Zfp6q2kOqblvYwmig==
X-Received: by 2002:a2e:a804:0:b0:288:d4ab:a323 with SMTP id l4-20020a2ea804000000b00288d4aba323mr1717705ljq.227.1674635146697;
        Wed, 25 Jan 2023 00:25:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4c8:8384:83f3 with SMTP id
 s15-20020a056512214f00b004c8838483f3ls8934773lfr.3.-pod-prod-gmail; Wed, 25
 Jan 2023 00:25:45 -0800 (PST)
X-Received: by 2002:a19:6a06:0:b0:4cc:73ec:c3d4 with SMTP id u6-20020a196a06000000b004cc73ecc3d4mr7232394lfu.63.1674635145483;
        Wed, 25 Jan 2023 00:25:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674635145; cv=none;
        d=google.com; s=arc-20160816;
        b=Vw/KEJGkihUSQsSgQ7iSGpVGbwICY6rPhxCw+JKa79pAe2K8DPIOogRzvS0fLXeuz+
         AcAStCyb40DbEp2XbW0rM6E0WjnPAhHgTe96fEcD8nMJJhl2AXt7a/7DDD87AAMhN043
         ojd5e1jtBqlpFsPhhpQgLUAsVolr6hDuS8P8FZqMd9QT+bDXdXVUxvdXJzds3rzIfBy4
         BGnqBBMfOA2e7JOSiAB9MzcT70+vGKDECsh+MgWYc3qzdMj0hKrFyajzvAiWEwnc5PQv
         7MFKWB8iFMZt/LVmv/HRjVPGd3t8zD9U3lmPQx/d415bjiPhkmq6LN0lE9jzXFV+RERu
         tFJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VsW9sZ9JYOT6czRlM5LOuE5iXgLFzYDpVH9ZLI+xY2k=;
        b=RsJz2O+JhBOn+FnoZgDKnoNylglsd9yex2yG1mrWsPbE4sIiNDHsNBFfRPoQPD7QNV
         XBtuRVmz0g7GbLgGjmZZpDqZG1I1qQehjHjUtR7mHpx7dfsX4IpRiRFMCM0sqsirEXny
         HKcGT3z97Fry9iPU4G0dE8bJmUyqqWN/lm0Pn0gjUrZlraQNxoOH4qijy/vVk9m7OBu5
         Znpcdon6VAQFe8TrNIdtWLEopj5qTE9RJN4FlFW3tvF690eQJNkQ0Rx5uyyLA5hEMqcY
         40mB79gzB4MhnAad1+W61blMRa+vGrOpAwvhkSmk7Z8PmRqiExAGsaziJbAc43IZhZlO
         /BgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=lPB1mHHn;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id q26-20020a19a41a000000b004a222ff195esi244500lfc.11.2023.01.25.00.25.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 00:25:45 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id f25-20020a1c6a19000000b003da221fbf48so682018wmc.1
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 00:25:45 -0800 (PST)
X-Received: by 2002:a05:600c:600e:b0:3c6:e62e:2e74 with SMTP id az14-20020a05600c600e00b003c6e62e2e74mr27751785wmb.15.1674635145100;
        Wed, 25 Jan 2023 00:25:45 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id w19-20020a05600c099300b003cfd4e6400csm1118048wmp.19.2023.01.25.00.25.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 00:25:44 -0800 (PST)
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
	Conor Dooley <conor@kernel.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v3 2/6] riscv: Rework kasan population functions
Date: Wed, 25 Jan 2023 09:23:29 +0100
Message-Id: <20230125082333.1577572-3-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230125082333.1577572-1-alexghiti@rivosinc.com>
References: <20230125082333.1577572-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=lPB1mHHn;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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
 arch/riscv/mm/kasan_init.c | 361 +++++++++++++++++++------------------
 1 file changed, 183 insertions(+), 178 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 2a48eba6bd08..5c7b1d07faf2 100644
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
-		memcpy(base_p4d, (void *)kasan_early_shadow_p4d,
-		       sizeof(p4d_t) * PTRS_PER_P4D);
+	if (pgd_none(*pgd)) {
+		p = memblock_alloc(PTRS_PER_P4D * sizeof(p4d_t), PAGE_SIZE);
+		set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
 	}
 
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
-}
-
-static void __init kasan_shallow_populate_pmd(pgd_t *pgdp,
-					      unsigned long vaddr, unsigned long end)
-{
-	unsigned long next;
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
 }
 
-static void __init kasan_shallow_populate_pud(pgd_t *pgdp,
+static void __init kasan_shallow_populate_pud(p4d_t *p4d,
 					      unsigned long vaddr, unsigned long end)
 {
 	unsigned long next;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125082333.1577572-3-alexghiti%40rivosinc.com.
