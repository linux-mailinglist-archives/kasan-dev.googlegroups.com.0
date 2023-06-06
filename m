Return-Path: <kasan-dev+bncBDXY7I6V6AMRB4W57SRQMGQEC4B3MUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E214724390
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Jun 2023 15:04:51 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-3f69613ffdfsf1127985e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Jun 2023 06:04:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686056691; cv=pass;
        d=google.com; s=arc-20160816;
        b=s+Q8ymWqqbFmjppk8xPpyaDfpvPiIUyloqEDntoBKu1QFJ2ZHnNJxx+Dp4x70p8WMc
         VrdGdfOBvQYYuqxG7Cia0qevTN5lJxqHWtMHnaDyHwvKBhPxyl9RKqBLumEYs94KE7K6
         B2UisbP8Z4TUMAnlH2DjTGMXTPpu8irWJ0Q3OUt8Lv0+QZpRKhR/auESsGdtsn4YmCO1
         X75ke3f2dBPmzKVgwr69YJ9qhl+mAQrwZjg0SCbBqKzYi0fQkQAxWFalvt0NK55RzaO4
         UHSolHKVhFvUIfRRwnnDJQbkGOhVygcBLeD1eHzc/CJuw6G30qJKLqgDgXV89El39f9Y
         Z3LQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=EVrxagws/MaRkmLZjMwGxOUMPXMTOAXmE7z61sSiswI=;
        b=cG+fErbgsxchLTL2QR0OzKuc3Ms1UI/GArwkmmuGnWuGgzXPv54kOQ/9Xb9Rbz/fnX
         /oTFT2gInvYk+HFkSbkCRmwKAoydTqDir0a4q1aOsS/y7p5usMce5M7dKQ+TppkCdnJ2
         xzjyZD6pxf2bQQb4HgUNejwvwwwvaw3izA//MVkQwZ/vGN2mapwCaZ6tZ4VlSD58bdt8
         r+axH2GoC9nFzmnBW48or+fJrQl4frwwCWDEoxQb06JIEiXoPwJLg0MfB5H7WPOB0WSs
         pX78fKD8X6gc4pUgLYIBhtfGrs9lGZX3eaW9GcEMtO2q0lrHQ0R3THnuLh5hrCQ4+BDm
         GGSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208 header.b=ASVrj5tM;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686056691; x=1688648691;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EVrxagws/MaRkmLZjMwGxOUMPXMTOAXmE7z61sSiswI=;
        b=iBu58iLhv96SkqpynR9vyKhPWfW+kNYyCIJON/WcYqudC8rQ+3XVtL1bENuasBb2u/
         sxUZrFndBJ7MbOdRUlgrhsme3rrMaOTBFgW46Nh5a7KiIgVFzkrfpW15xV5vzEHqB8YF
         vUojdWBeQaDykxLJlhIqmlC9VKbhez7bkpsz2Qz85zkd0MidH1ndwT9/kX6BbQu4D8rG
         m31uzji/RIFH2CSVlJy2+ysp1WAXvWd7qdP0byQa7nGFQt0HCc3rZ+RlfxenkyhGbrvU
         rZXA92PqHjHp//kPYQIcF0pHmt9OyCRo8+MuRF0+ypbKRBTRTqU68lAQGQK+vqJgVJek
         3ghw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686056691; x=1688648691;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EVrxagws/MaRkmLZjMwGxOUMPXMTOAXmE7z61sSiswI=;
        b=bCOF5fi/vjee0vO7AK8qaNvduuikFqqIjYAv3MNuYmWY2ElsOLHcsNCHET3IVX8Tvf
         hVMb2aLxy4JmGiYkmI9nDktiJQ5pz5fwOXi78SKd5IzFaFW/I2ZzOgsWc06MWfvB7ti/
         5wJ+Y6ZVouc+47+m2F6mMOQBYahPYY6UjN4m8NS+YQbBSWuShNoGnhzX9KFXEKzt5fe9
         5+9yw+1gIy9kn105s5IXeXUS0+0MO4035O9rq2gCd/hLQ6eM9IqRR8PL+nH52Iz3cKsP
         bfbtU6Xg+DyI7hM8uXTKgprER9k/3t9J0zIbPz5kJmWOfqw9YPvnqbmBIvjq7NpkJx4s
         F3NA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx24tDqkyLt1ZRfoGqtmU7FY7zpFR69YEQxa+daI5MWfReDHe56
	tTqphSlkjX4vDG1ezkSHLgU=
X-Google-Smtp-Source: ACHHUZ7Ho3EzjMH3zMExkRs8TADL6glyqilK8KAqaMtGgSB2YTAhQM+LU4U/4XTbOFpufW2G06dRQA==
X-Received: by 2002:a05:600c:3153:b0:3f4:fb7:48d4 with SMTP id h19-20020a05600c315300b003f40fb748d4mr127085wmo.3.1686056690424;
        Tue, 06 Jun 2023 06:04:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:b8b:b0:3f7:e710:c2c9 with SMTP id
 fl11-20020a05600c0b8b00b003f7e710c2c9ls607166wmb.0.-pod-prod-04-eu; Tue, 06
 Jun 2023 06:04:48 -0700 (PDT)
X-Received: by 2002:a05:600c:2291:b0:3f6:48e:92ca with SMTP id 17-20020a05600c229100b003f6048e92camr1819849wmf.39.1686056688812;
        Tue, 06 Jun 2023 06:04:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686056688; cv=none;
        d=google.com; s=arc-20160816;
        b=ceFJ9FsRFaU8vNrwNiAgvtMWGtSVJGbZxPjw8efEiTulmS9Bor8dcDjqXXup5PzX+I
         0y6W4k4OEHcXNRP1OD7g3MgPCTcz9UW+hCMvActJfGPtYpFva8IDaM4eS9BC2MDOZ7Hq
         i5noVBEaZfpQyHkBZ2bVrxilgQGCbY58XvGleRKQGdde4AuBaARDamxWZ8b2nEdSm+bm
         5uOr0+VgB2jVWsUmJRyOgrygN3fL324XX+kFwJUVz/yNLWFLv/GRq3FQQMcD19N8tBMs
         /wdouh+KjONV5/wjN/gYi5GG/YW3/2vkgQnilyHzww0CplibKPQ1YNiKIIWOmAqLKbEK
         3OYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=b3haPEvDRoJ3tYhZAI4EXu9621m3NDLWoNUUl1GQmAY=;
        b=LAVPbUZfBZhY5xBOWf7CnC4jc/xpkL2WjE9E14bWxF3JG8GX3PF70bHT32NWpn/Ean
         msHVTgerSEXXfPO80/0SH+wfpNj1l1vdFNHvnPmi7lkgt8mW2FmoNUo3Ayyr/uKf92GE
         uWjBeF79iIwAOlMHUfzVZhE7XnguAO8yxA1IQ7uGV1me41+/54nnrU3FugVAyMmM0NF7
         SQcY/aH9Eo4Kf0oRr9QJ0k3PNnihBsFkyd2ztBZXVm/ZgyHtAoT4VL9BxTE1JiouJxzA
         yfH0y+mYAxUZxbIxND/cmI8yqZ81ycOouvWdhGE8I8gDzxzAhvN2RI11AISriEzgEvys
         K/Ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208 header.b=ASVrj5tM;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id gy10-20020a05600c880a00b003f7e7e76d04si315103wmb.0.2023.06.06.06.04.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Jun 2023 06:04:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-30aef0b8837so4974924f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 06 Jun 2023 06:04:48 -0700 (PDT)
X-Received: by 2002:adf:fac2:0:b0:30a:e097:7b5a with SMTP id a2-20020adffac2000000b0030ae0977b5amr1469605wrs.36.1686056688406;
        Tue, 06 Jun 2023 06:04:48 -0700 (PDT)
Received: from localhost.localdomain (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id h9-20020a056000000900b002f9e04459desm12759236wrx.109.2023.06.06.06.04.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Jun 2023 06:04:48 -0700 (PDT)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Rob Herring <robh@kernel.org>,
	Anup Patel <anup@brainfault.org>,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Andrew Jones <ajones@ventanamicro.com>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org
Cc: syzbot+a74d57bddabbedd75135@syzkaller.appspotmail.com
Subject: [PATCH] riscv: Fix kfence now that the linear mapping can be backed by PUD/P4D/PGD
Date: Tue,  6 Jun 2023 15:04:44 +0200
Message-Id: <20230606130444.25090-1-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208
 header.b=ASVrj5tM;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

RISC-V Kfence implementation used to rely on the fact the linear mapping
was backed by at most PMD hugepages, which is not true anymore since
commit 3335068f8721 ("riscv: Use PUD/P4D/PGD pages for the linear
mapping").

Instead of splitting PUD/P4D/PGD mappings afterwards, directly map the
kfence pool region using PTE mappings by allocating this region before
setup_vm_final().

Reported-by: syzbot+a74d57bddabbedd75135@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=a74d57bddabbedd75135
Fixes: 3335068f8721 ("riscv: Use PUD/P4D/PGD pages for the linear mapping")
Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/include/asm/kfence.h | 33 -------------------------------
 arch/riscv/mm/init.c            | 35 ++++++++++++++++++++++++++++-----
 2 files changed, 30 insertions(+), 38 deletions(-)

diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
index d887a54042aa..0bbffd528096 100644
--- a/arch/riscv/include/asm/kfence.h
+++ b/arch/riscv/include/asm/kfence.h
@@ -8,41 +8,8 @@
 #include <asm-generic/pgalloc.h>
 #include <asm/pgtable.h>
 
-static inline int split_pmd_page(unsigned long addr)
-{
-	int i;
-	unsigned long pfn = PFN_DOWN(__pa((addr & PMD_MASK)));
-	pmd_t *pmd = pmd_off_k(addr);
-	pte_t *pte = pte_alloc_one_kernel(&init_mm);
-
-	if (!pte)
-		return -ENOMEM;
-
-	for (i = 0; i < PTRS_PER_PTE; i++)
-		set_pte(pte + i, pfn_pte(pfn + i, PAGE_KERNEL));
-	set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(pte)), PAGE_TABLE));
-
-	flush_tlb_kernel_range(addr, addr + PMD_SIZE);
-	return 0;
-}
-
 static inline bool arch_kfence_init_pool(void)
 {
-	int ret;
-	unsigned long addr;
-	pmd_t *pmd;
-
-	for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
-	     addr += PAGE_SIZE) {
-		pmd = pmd_off_k(addr);
-
-		if (pmd_leaf(*pmd)) {
-			ret = split_pmd_page(addr);
-			if (ret)
-				return false;
-		}
-	}
-
 	return true;
 }
 
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 747e5b1ef02d..d42ea31c7de0 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -23,6 +23,7 @@
 #ifdef CONFIG_RELOCATABLE
 #include <linux/elf.h>
 #endif
+#include <linux/kfence.h>
 
 #include <asm/fixmap.h>
 #include <asm/tlbflush.h>
@@ -1167,14 +1168,16 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 }
 
 static void __init create_linear_mapping_range(phys_addr_t start,
-					       phys_addr_t end)
+					       phys_addr_t end,
+					       uintptr_t fixed_map_size)
 {
 	phys_addr_t pa;
 	uintptr_t va, map_size;
 
 	for (pa = start; pa < end; pa += map_size) {
 		va = (uintptr_t)__va(pa);
-		map_size = best_map_size(pa, end - pa);
+		map_size = fixed_map_size ? fixed_map_size :
+					    best_map_size(pa, end - pa);
 
 		create_pgd_mapping(swapper_pg_dir, va, pa, map_size,
 				   pgprot_from_va(va));
@@ -1184,6 +1187,7 @@ static void __init create_linear_mapping_range(phys_addr_t start,
 static void __init create_linear_mapping_page_table(void)
 {
 	phys_addr_t start, end;
+	phys_addr_t kfence_pool __maybe_unused;
 	u64 i;
 
 #ifdef CONFIG_STRICT_KERNEL_RWX
@@ -1197,6 +1201,19 @@ static void __init create_linear_mapping_page_table(void)
 	memblock_mark_nomap(krodata_start, krodata_size);
 #endif
 
+#ifdef CONFIG_KFENCE
+	/*
+	 *  kfence pool must be backed by PAGE_SIZE mappings, so allocate it
+	 *  before we setup the linear mapping so that we avoid using hugepages
+	 *  for this region.
+	 */
+	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+	BUG_ON(!kfence_pool);
+
+	memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
+	__kfence_pool = __va(kfence_pool);
+#endif
+
 	/* Map all memory banks in the linear mapping */
 	for_each_mem_range(i, &start, &end) {
 		if (start >= end)
@@ -1207,17 +1224,25 @@ static void __init create_linear_mapping_page_table(void)
 		if (end >= __pa(PAGE_OFFSET) + memory_limit)
 			end = __pa(PAGE_OFFSET) + memory_limit;
 
-		create_linear_mapping_range(start, end);
+		create_linear_mapping_range(start, end, 0);
 	}
 
 #ifdef CONFIG_STRICT_KERNEL_RWX
-	create_linear_mapping_range(ktext_start, ktext_start + ktext_size);
+	create_linear_mapping_range(ktext_start, ktext_start + ktext_size, 0);
 	create_linear_mapping_range(krodata_start,
-				    krodata_start + krodata_size);
+				    krodata_start + krodata_size, 0);
 
 	memblock_clear_nomap(ktext_start,  ktext_size);
 	memblock_clear_nomap(krodata_start, krodata_size);
 #endif
+
+#ifdef CONFIG_KFENCE
+	create_linear_mapping_range(kfence_pool,
+				    kfence_pool + KFENCE_POOL_SIZE,
+				    PAGE_SIZE);
+
+	memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
+#endif
 }
 
 static void __init setup_vm_final(void)
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230606130444.25090-1-alexghiti%40rivosinc.com.
