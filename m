Return-Path: <kasan-dev+bncBAABB6F5S2FAMGQEGHM7H3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id A001F410508
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 10:10:33 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id w20-20020a4a7654000000b002917fdff67fsf40264254ooe.2
        for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 01:10:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631952632; cv=pass;
        d=google.com; s=arc-20160816;
        b=YT1vrYriFqceIRv33jneuESN15pcUdC2Vl5qpp1fQrJIyEp5GpPZkhvlnxVoZjyW7k
         OSn10mzZmFbNCfQaCO7LR43r97hiSVr/eedPtKDSUNXJlJpq/vpb+qLF3NwkTmOTK2sp
         sWOO49qVvbI+3UCLOIJu8dLQgN8ZEyholOByqIBmjoAm18wisrc62KFj35+N+ci38I7A
         Tn5/VMUM1DA8Xm23OWeeC6HUdZo+gQOa8SnkOop6nJQmsP2miNYueeQvESwJA1HCQ9Cx
         8jmzjnJCIq434fuzdocTTVaphf/PTEUMOjX3ENFs/x1NGUvvjUCpIfHmlH1mPIUtuzC/
         /ztQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=4QC3sLzwR6rF6D48wECKMaM6dO4RuKsLMOdr+7CMW8Q=;
        b=tOsyRiUh7L6BiVA+Ng+oxbzR4Xma6WpzEJmohcwCbJoBqAKlX+jFa7ofdEXe95rZRS
         u8W6cl0XD82scYpIboztZqP8FiIE1BOqAVbMiC3puhnMx/N+0pD+qnUg8BEQZzJUCIhI
         Q3dQgfgfKgzOFa3N7IHGa3O/ozSckq8O4niu7FATsKN+SUOFbWdmoFfsA2cDAKPbnKUD
         dH2y/eWJFaAuene1wTNTg4G8AGyKozZhM3ZztMekuKcSinOysJ9ScSHvWFfDJS4rHKjd
         apya/B7T3K1Pjgw9JWDxOTuhBkGF7P3aJ1DU0T5BmrpG/JRXaJiAfOR1nQB8LoYAh1JX
         e+vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4QC3sLzwR6rF6D48wECKMaM6dO4RuKsLMOdr+7CMW8Q=;
        b=Q7hcnNHnAF9ZcwWVYnEt5YjprIVyJzkeadi2ZzvWR/lVG25jfstGLVzR1QBY9msIGD
         IkYbV6+iADeDtAqZ234yIWkevCFdQ2uJizMwpkv1yeLc+JxjqOOBDFeVoJbDY0xmQdYY
         gwsb2slC3JKRMSo7FTlmmHKoFx/1nKuylQBqBnQiAOFIrw7wXkiggfi6q9W0UkB3DORn
         UGXYw4f4Kzb0/k6wF9fbgsHRcNIQ1hyydEPQnk7Jymm/vg9xrb8UbDRBDUXIQgULLsmG
         mBaNGW6bbKYrYHst/tTL435Lg4YI8CkVF1tcg1gxemTR7jwMnn/JsCFkgmMo60CyF/s3
         ySdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4QC3sLzwR6rF6D48wECKMaM6dO4RuKsLMOdr+7CMW8Q=;
        b=UuR6AhgSBE/hziW7j1FOPoTs/p7S5Oa6L/HZ+SdYZzLySUd86vhvNV0wEup4Uw/OEU
         nhjr2oj+rPIu6RPA5UT+A9O0StBnfImZ0y/j6LCunRYn/MSpcC1en10egWFtYeeYvIm0
         osYMsomfaPAzDC/iYyEuwAlFttSjnuTOxo0oktTxZUiBnaWOyl1fFZ4FE+yXE/0J0nfA
         uNKODYIdpK2pwb2vt93+2TtoENQ3sivGnEvpA54CwEVkb83aXPwriJEyP3bIIIZc8kA0
         qegIGA2WNc+oE3KQHTmKa1+vnDBwhy7Q328v+9HuwFoMX560C/UDPy/J6HIwUM2yZbn2
         bBbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lTKGr3W7+ag7QS0pAVi8aPGSgazilitEqThTBCWX0c5tYIvqa
	nZlX5y7LbadCp/1onIt/vEo=
X-Google-Smtp-Source: ABdhPJzb7T9fP8SkbHvPqLMHiY0LUCWX07Ywt8kKvz0UYR8ZpSFHTUHUCZb3JktbnqVI9StkhsVhyw==
X-Received: by 2002:aca:1706:: with SMTP id j6mr590223oii.57.1631952632434;
        Sat, 18 Sep 2021 01:10:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:62c9:: with SMTP id z9ls3750856otk.6.gmail; Sat, 18 Sep
 2021 01:10:32 -0700 (PDT)
X-Received: by 2002:a05:6830:797:: with SMTP id w23mr1839268ots.109.1631952632108;
        Sat, 18 Sep 2021 01:10:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631952632; cv=none;
        d=google.com; s=arc-20160816;
        b=RoGUU+pZg26ebwGXiFidUV/tycjoSJpWAC9USGA9ifnWr/qz8FciCQslsUsEXKybRy
         /SyH2XXNzivJr+rryQAal/jPrfxbk/XZ1z9MB1qMfcCqoejyzHhLxdPYGWpzbvWvQG3D
         Fci1pmKHk9mDbNqUSUsJS17ZdsMHOsU0OVug7Dac4nu4jsE5rJE/jIvPyOqZebnROmzp
         7clTxRnCHIeOLrllDRmJzUxv5DE1X2F+yzPsMGpQInXCAo6KAO6TSnXD85oNmva/Al9g
         uvB0VA/WGKLhBeL6JzADsVSOeN19EhfXpLmf4OWWoC2sL8puOtLgsPrYLppuxk68Uu2e
         /K/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=5MEmtDqmwsf18OZjVG2jUJPEBi47fugTLa0/bpZdSPM=;
        b=JACb0DDnoq7VFz4Rf8e9pacvXEYiuaEM5+IPnCLNDa35SH0u9cXDngCTHpzcJX05fV
         pPuGuWHMK5P+OmTF2QaD+XeaOfIR0VbtOy3b7yQgmIKALl7qfnG7KFx2rGE+UA6Gde47
         bKA/ZbSvVF7m+mcSVPJh7fVEFCJWeAFrvsgaZOz0aZFkjqKXuA2FrjDh68YdzOw6KcXC
         htpFb7/0ICVSqTWVpjZqySTk5HRRoMjRUAn8FNeZYNrBSbvYUD2okDGQOd4NmW5OyfCz
         TmfePYtwxCkK3FO9nSqXT6qdr/+5RZz59YGwWwKHxO9tYtIfmMZ6gh84R7QV31wKrEnm
         UoTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id d24si721425ote.2.2021.09.18.01.10.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 18 Sep 2021 01:10:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4HBNgF07rGz8yQD;
	Sat, 18 Sep 2021 16:06:01 +0800 (CST)
Received: from dggpemm500009.china.huawei.com (7.185.36.225) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Sat, 18 Sep 2021 16:10:30 +0800
Received: from huawei.com (10.175.113.32) by dggpemm500009.china.huawei.com
 (7.185.36.225) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2308.8; Sat, 18 Sep
 2021 16:10:29 +0800
From: Liu Shixin <liushixin2@huawei.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Catalin Marinas
	<catalin.marinas@arm.com>, Will Deacon <will@kernel.org>
CC: <kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, Liu Shixin <liushixin2@huawei.com>
Subject: [PATCH] arm64: remove page granularity limitation from KFENCE
Date: Sat, 18 Sep 2021 16:38:49 +0800
Message-ID: <20210918083849.2696287-1-liushixin2@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.32]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500009.china.huawei.com (7.185.36.225)
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=liushixin2@huawei.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

Currently if KFENCE is enabled in arm64, the entire linear map will be
mapped at page granularity which seems overkilled. Actually only the
kfence pool requires to be mapped at page granularity. We can remove the
restriction from KFENCE and force the linear mapping of the kfence pool
at page granularity later in arch_kfence_init_pool().

Signed-off-by: Liu Shixin <liushixin2@huawei.com>
---
 arch/arm64/include/asm/kfence.h | 69 ++++++++++++++++++++++++++++++++-
 arch/arm64/mm/mmu.c             |  4 +-
 2 files changed, 70 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
index aa855c6a0ae6..bee101eced0b 100644
--- a/arch/arm64/include/asm/kfence.h
+++ b/arch/arm64/include/asm/kfence.h
@@ -8,9 +8,76 @@
 #ifndef __ASM_KFENCE_H
 #define __ASM_KFENCE_H
 
+#include <linux/kfence.h>
 #include <asm/set_memory.h>
+#include <asm/pgalloc.h>
 
-static inline bool arch_kfence_init_pool(void) { return true; }
+static inline int split_pud_page(pud_t *pud, unsigned long addr)
+{
+	int i;
+	pmd_t *pmd = pmd_alloc_one(&init_mm, addr);
+	unsigned long pfn = PFN_DOWN(__pa(addr));
+
+	if (!pmd)
+		return -ENOMEM;
+
+	for (i = 0; i < PTRS_PER_PMD; i++)
+		set_pmd(pmd + i, pmd_mkhuge(pfn_pmd(pfn + i * PTRS_PER_PTE, PAGE_KERNEL)));
+
+	smp_wmb(); /* See comment in __pte_alloc */
+	pud_populate(&init_mm, pud, pmd);
+	flush_tlb_kernel_range(addr, addr + PUD_SIZE);
+	return 0;
+}
+
+static inline int split_pmd_page(pmd_t *pmd, unsigned long addr)
+{
+	int i;
+	pte_t *pte = pte_alloc_one_kernel(&init_mm);
+	unsigned long pfn = PFN_DOWN(__pa(addr));
+
+	if (!pte)
+		return -ENOMEM;
+
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		set_pte(pte + i, pfn_pte(pfn + i, PAGE_KERNEL));
+
+	smp_wmb(); /* See comment in __pte_alloc */
+	pmd_populate_kernel(&init_mm, pmd, pte);
+
+	flush_tlb_kernel_range(addr, addr + PMD_SIZE);
+	return 0;
+}
+
+static inline bool arch_kfence_init_pool(void)
+{
+	unsigned long addr;
+	pgd_t *pgd;
+	p4d_t *p4d;
+	pud_t *pud;
+	pmd_t *pmd;
+
+	for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
+	     addr += PAGE_SIZE) {
+		pgd = pgd_offset(&init_mm, addr);
+		if (pgd_leaf(*pgd))
+			return false;
+		p4d = p4d_offset(pgd, addr);
+		if (p4d_leaf(*p4d))
+			return false;
+		pud = pud_offset(p4d, addr);
+		if (pud_leaf(*pud)) {
+			if (split_pud_page(pud, addr & PUD_MASK))
+				return false;
+		}
+		pmd = pmd_offset(pud, addr);
+		if (pmd_leaf(*pmd)) {
+			if (split_pmd_page(pmd, addr & PMD_MASK))
+				return false;
+		}
+	}
+	return true;
+}
 
 static inline bool kfence_protect_page(unsigned long addr, bool protect)
 {
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index cfd9deb347c3..b2c79ccfb1c5 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -516,7 +516,7 @@ static void __init map_mem(pgd_t *pgdp)
 	 */
 	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
 
-	if (can_set_direct_map() || crash_mem_map || IS_ENABLED(CONFIG_KFENCE))
+	if (can_set_direct_map() || crash_mem_map)
 		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
 
 	/*
@@ -1485,7 +1485,7 @@ int arch_add_memory(int nid, u64 start, u64 size,
 	 * KFENCE requires linear map to be mapped at page granularity, so that
 	 * it is possible to protect/unprotect single pages in the KFENCE pool.
 	 */
-	if (can_set_direct_map() || IS_ENABLED(CONFIG_KFENCE))
+	if (can_set_direct_map())
 		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
 
 	__create_pgd_mapping(swapper_pg_dir, start, __phys_to_virt(start),
-- 
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210918083849.2696287-1-liushixin2%40huawei.com.
