Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBMGVW6GQMGQE2HQZXSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D558469436
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 11:49:21 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id k15-20020adfe8cf000000b00198d48342f9sf1914724wrn.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 02:49:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638787761; cv=pass;
        d=google.com; s=arc-20160816;
        b=qWk3sYlRbI6dObMhV5YnF5vcXM3fWKG0W5Y2KkLlICDBnhE4HG0W1LE9SvVimrFqm0
         tBxsEnO+DGJWs5u4OBbusfQZJYSQLsj5nSmKmD6169sdP/3q0wa8ru0GYdCQDdzuxowQ
         kQSWpn3glTz/IJuguLbgv4PcUEZcwrqlu+V/k5GT2pCf6C0f53Omx2vH6UcUrcmCJbRV
         uZKIHTG0wEMfTXYZbjTIQ7xfzTNGg7QiKFNUltRv87g+tJ3xPZ96ARLzX8bKDTMc79xP
         4ceVFVqaZ2bmid9+AM9mefbVfuEywRS/bUlLb1Rur0O3Y81D8iqJb1L9c9Hn6nlNFVhA
         K/KA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ELV313Zk3jK0npNstq0TkfIgEgkoCyqTSQnZ/mDlLeQ=;
        b=g3DiXrrxWL931Eo0rukGngPvzXh9Ny91GIUzDPpU4373yuejmHB/LLlgSWZs5cnRXX
         ttWYP+0zx+N0XCrdMYXeTc4BkbdKFvYBpp4MLy65wjsQsDzp4rn1p7r76A+zoRCbkpf8
         u853BPaS2WLpCJaOmAxNBBnEyn7wjB3qXVt7UfRGaNGbexePaAb4MJlJSpW6NOIHlnto
         l+QahQOQpFx0d+voYEgSoo3LgNNdYR2QlIvArrZQI2fsCJP78QmQtpx1jKms6TDbSwg+
         FfiDQxaPMGJw/hxNRb/OAFL7vk6rkLNg/6Oa/ccXtsmUNW1S/WCCXc6XazDz6fmYUs9b
         7b7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=ON5x4H32;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ELV313Zk3jK0npNstq0TkfIgEgkoCyqTSQnZ/mDlLeQ=;
        b=IGAU7xM4cKSbbyA1bUD8BuhHj17hcmznAVKyAorfH4zeUDtFD8AHj2J/oSzWZE/yAZ
         tqbjuMN3h2rF9CPBzegbQB/wY1zLbdob7xnN6j4rE3zkStVhJh+1m6twu8GC/7I8gT5V
         u9bM3DTxYSO+Bme12JKFr7msQrG4k5TBJUdJF2CeChpfvRhhPouYW9NkNbdJY817s16b
         qoEIRkhFW8ZwvHAiaWTiCXJWlip26vahXHvAHHXIvnAyJD1OaJ1zKhZeirR6GwwDo14m
         j/UFiVHuKJQ8HpUwLeRvE69CVmPu0s5Rlredi0zHtzDhAOOp/zB7kNm9ouocVcgadC0Q
         1kUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ELV313Zk3jK0npNstq0TkfIgEgkoCyqTSQnZ/mDlLeQ=;
        b=K1IxM93LVRE9Axi5/GZtGtFPsgcZj9iPhMTEbXE7R95+iYyn1KH+u9rl7iu4Ef8aNi
         zVTkUEdc3BVCYRpxZJshoYmQnmZ3/MrEtEathMmEsXH/VPLl34zEqD+gzh+/3JaJVkeI
         xpW/OOIT/3JuvVjYobJdVtxJuY2Z+1Lmq/Lt6L8tBDJ/eftNru6wJq3G6momSAR4O9z3
         9I0SZcCk8b2cuJmX8pfsEnxRlT0ify7ZtlGrXeT91i/7330WutW95h6zkOOJWK9XgLtT
         JJ0AYEDUDGfQqtB7whGe82qHK2AZT/BlshZEB2ow+uzXGJD5W7Qcw8VYt7Q3aOS3j1Vs
         FL/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531kXi3PU8i2Q8YJL7Pt+R8EBomK54QgF1pY5LkE9kBbGgQGYx7L
	YDCdrR3EVutzACQjIgzPLnw=
X-Google-Smtp-Source: ABdhPJwphOQR6cGFZPvQ3db68vt7fnJFuqiaX6tqKh8OmUa6nwFFEHlM7eG7+Nyqx1fCJSHQHoMifg==
X-Received: by 2002:a5d:4989:: with SMTP id r9mr41295352wrq.14.1638787760911;
        Mon, 06 Dec 2021 02:49:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:80c3:: with SMTP id b186ls7914742wmd.2.gmail; Mon, 06
 Dec 2021 02:49:20 -0800 (PST)
X-Received: by 2002:a1c:1b15:: with SMTP id b21mr38072640wmb.174.1638787760109;
        Mon, 06 Dec 2021 02:49:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638787760; cv=none;
        d=google.com; s=arc-20160816;
        b=VhsjXlmuzloDQfbSI9nv+sh3g5G3/YOAsIXRj2HbdOYmuNWIK5dmt1SJdVsvcis/dU
         PbSHPqGjYDTZuJ4lj816ZaBQCG6y7bU3mS/Kv8TXfdF5edlkIGb8YJgmr5I3tDE6CqAf
         5ihaNuOWt2R7BT49CVqzLQFQcqn902duwIy9AHTVTJWrD0BvkOsFx8Y6951pa8Z3ZPGx
         dsAELeicseWm2dR5xJWL1ptXH1podVgp1yBTChPkkRQJk853wrdBG2nXA75gLv3IecuF
         N3IdL8xnHLCtHRq+m1CumXOF5W/8Kt4hpETq31Gcu7Hd3QPB7Tl/J3o2iNCRaJI4eikL
         KpRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SRQqaE+eBxp32u4NFRGojAHgHUNJ3nLFCtcyJRkcDak=;
        b=JuZbr9Z3mvx+7hdiSAkWWG7W5QqDvRSMsZfrLBHPjmHf/MtU7rYJbp700I3NhCYH+h
         s6pKk+QhBZk00bJwE/Y8qonjq6t9qCvZdddDUlio66RJw4ALtfpb+TW4lWTQLnrglHUD
         /1TL2jkIY3HK/4wUrR7o/SnG923KVgrSmpKGerbpj1mupzGPbE8twnK3eBmMxpgQMedZ
         H5MJoq0bZCpNr3esGd8BaSrMAP1lc0dwNlPiBeq046jVqTY2+HJVZUfy878E1wGWd//r
         iLlEHaEUA//X2pQwwvVdcrwQUqsYrCFCqskkmQ1yS8riDCe1N1XcQ5xePEyulepNAPXF
         R3hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=ON5x4H32;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id s138si837706wme.1.2021.12.06.02.49.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:49:20 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com [209.85.128.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id A8D4440040
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 10:49:19 +0000 (UTC)
Received: by mail-wm1-f70.google.com with SMTP id n41-20020a05600c502900b003335ab97f41so4318358wmr.3
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 02:49:19 -0800 (PST)
X-Received: by 2002:adf:efc6:: with SMTP id i6mr40936988wrp.428.1638787759176;
        Mon, 06 Dec 2021 02:49:19 -0800 (PST)
X-Received: by 2002:adf:efc6:: with SMTP id i6mr40936958wrp.428.1638787758943;
        Mon, 06 Dec 2021 02:49:18 -0800 (PST)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id m21sm11197860wrb.2.2021.12.06.02.49.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:49:18 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@rivosinc.com>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Guo Ren <guoren@linux.alibaba.com>,
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
	Mayuresh Chitale <mchitale@ventanamicro.com>,
	panqinglin2020@iscas.ac.cn,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v3 02/13] riscv: Split early kasan mapping to prepare sv48 introduction
Date: Mon,  6 Dec 2021 11:46:46 +0100
Message-Id: <20211206104657.433304-3-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=ON5x4H32;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

Now that kasan shadow region is next to the kernel, for sv48, this
region won't be aligned on PGDIR_SIZE and then when populating this
region, we'll need to get down to lower levels of the page table. So
instead of reimplementing the page table walk for the early population,
take advantage of the existing functions used for the final population.

Note that kasan swapper initialization must also be split since memblock
is not initialized at this point and as the last PGD is shared with the
kernel, we'd need to allocate a PUD so postpone the kasan final
population after the kernel population is done.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/include/asm/kasan.h |   1 +
 arch/riscv/mm/init.c           |   4 ++
 arch/riscv/mm/kasan_init.c     | 113 ++++++++++++++++++---------------
 3 files changed, 67 insertions(+), 51 deletions(-)

diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
index 257a2495145a..2788e2c46609 100644
--- a/arch/riscv/include/asm/kasan.h
+++ b/arch/riscv/include/asm/kasan.h
@@ -34,6 +34,7 @@
 
 void kasan_init(void);
 asmlinkage void kasan_early_init(void);
+void kasan_swapper_init(void);
 
 #endif
 #endif
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 4224e9d0ecf5..5010eba52738 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -742,6 +742,10 @@ static void __init setup_vm_final(void)
 	create_kernel_page_table(swapper_pg_dir, false);
 #endif
 
+#ifdef CONFIG_KASAN
+	kasan_swapper_init();
+#endif
+
 	/* Clear fixmap PTE and PMD mappings */
 	clear_fixmap(FIX_PTE);
 	clear_fixmap(FIX_PMD);
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 54294f83513d..1434a0225140 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -12,44 +12,6 @@
 #include <asm/pgalloc.h>
 
 extern pgd_t early_pg_dir[PTRS_PER_PGD];
-asmlinkage void __init kasan_early_init(void)
-{
-	uintptr_t i;
-	pgd_t *pgd = early_pg_dir + pgd_index(KASAN_SHADOW_START);
-
-	BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
-		KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
-
-	for (i = 0; i < PTRS_PER_PTE; ++i)
-		set_pte(kasan_early_shadow_pte + i,
-			mk_pte(virt_to_page(kasan_early_shadow_page),
-			       PAGE_KERNEL));
-
-	for (i = 0; i < PTRS_PER_PMD; ++i)
-		set_pmd(kasan_early_shadow_pmd + i,
-			pfn_pmd(PFN_DOWN
-				(__pa((uintptr_t) kasan_early_shadow_pte)),
-				__pgprot(_PAGE_TABLE)));
-
-	for (i = KASAN_SHADOW_START; i < KASAN_SHADOW_END;
-	     i += PGDIR_SIZE, ++pgd)
-		set_pgd(pgd,
-			pfn_pgd(PFN_DOWN
-				(__pa(((uintptr_t) kasan_early_shadow_pmd))),
-				__pgprot(_PAGE_TABLE)));
-
-	/* init for swapper_pg_dir */
-	pgd = pgd_offset_k(KASAN_SHADOW_START);
-
-	for (i = KASAN_SHADOW_START; i < KASAN_SHADOW_END;
-	     i += PGDIR_SIZE, ++pgd)
-		set_pgd(pgd,
-			pfn_pgd(PFN_DOWN
-				(__pa(((uintptr_t) kasan_early_shadow_pmd))),
-				__pgprot(_PAGE_TABLE)));
-
-	local_flush_tlb_all();
-}
 
 static void __init kasan_populate_pte(pmd_t *pmd, unsigned long vaddr, unsigned long end)
 {
@@ -108,26 +70,35 @@ static void __init kasan_populate_pmd(pgd_t *pgd, unsigned long vaddr, unsigned
 	set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_pmd)), PAGE_TABLE));
 }
 
-static void __init kasan_populate_pgd(unsigned long vaddr, unsigned long end)
+static void __init kasan_populate_pgd(pgd_t *pgdp,
+				      unsigned long vaddr, unsigned long end,
+				      bool early)
 {
 	phys_addr_t phys_addr;
-	pgd_t *pgdp = pgd_offset_k(vaddr);
 	unsigned long next;
 
 	do {
 		next = pgd_addr_end(vaddr, end);
 
-		/*
-		 * pgdp can't be none since kasan_early_init initialized all KASAN
-		 * shadow region with kasan_early_shadow_pmd: if this is stillthe case,
-		 * that means we can try to allocate a hugepage as a replacement.
-		 */
-		if (pgd_page_vaddr(*pgdp) == (unsigned long)lm_alias(kasan_early_shadow_pmd) &&
-		    IS_ALIGNED(vaddr, PGDIR_SIZE) && (next - vaddr) >= PGDIR_SIZE) {
-			phys_addr = memblock_phys_alloc(PGDIR_SIZE, PGDIR_SIZE);
-			if (phys_addr) {
-				set_pgd(pgdp, pfn_pgd(PFN_DOWN(phys_addr), PAGE_KERNEL));
+		if (IS_ALIGNED(vaddr, PGDIR_SIZE) && (next - vaddr) >= PGDIR_SIZE) {
+			if (early) {
+				phys_addr = __pa((uintptr_t)kasan_early_shadow_pgd_next);
+				set_pgd(pgdp, pfn_pgd(PFN_DOWN(phys_addr), PAGE_TABLE));
 				continue;
+			} else if (pgd_page_vaddr(*pgdp) ==
+				   (unsigned long)lm_alias(kasan_early_shadow_pgd_next)) {
+				/*
+				 * pgdp can't be none since kasan_early_init
+				 * initialized all KASAN shadow region with
+				 * kasan_early_shadow_pud: if this is still the
+				 * case, that means we can try to allocate a
+				 * hugepage as a replacement.
+				 */
+				phys_addr = memblock_phys_alloc(PGDIR_SIZE, PGDIR_SIZE);
+				if (phys_addr) {
+					set_pgd(pgdp, pfn_pgd(PFN_DOWN(phys_addr), PAGE_KERNEL));
+					continue;
+				}
 			}
 		}
 
@@ -135,12 +106,52 @@ static void __init kasan_populate_pgd(unsigned long vaddr, unsigned long end)
 	} while (pgdp++, vaddr = next, vaddr != end);
 }
 
+asmlinkage void __init kasan_early_init(void)
+{
+	uintptr_t i;
+
+	BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
+		KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
+
+	for (i = 0; i < PTRS_PER_PTE; ++i)
+		set_pte(kasan_early_shadow_pte + i,
+			mk_pte(virt_to_page(kasan_early_shadow_page),
+			       PAGE_KERNEL));
+
+	for (i = 0; i < PTRS_PER_PMD; ++i)
+		set_pmd(kasan_early_shadow_pmd + i,
+			pfn_pmd(PFN_DOWN
+				(__pa((uintptr_t)kasan_early_shadow_pte)),
+				PAGE_TABLE));
+
+	if (pgtable_l4_enabled) {
+		for (i = 0; i < PTRS_PER_PUD; ++i)
+			set_pud(kasan_early_shadow_pud + i,
+				pfn_pud(PFN_DOWN
+					(__pa(((uintptr_t)kasan_early_shadow_pmd))),
+					PAGE_TABLE));
+	}
+
+	kasan_populate_pgd(early_pg_dir + pgd_index(KASAN_SHADOW_START),
+			   KASAN_SHADOW_START, KASAN_SHADOW_END, true);
+
+	local_flush_tlb_all();
+}
+
+void __init kasan_swapper_init(void)
+{
+	kasan_populate_pgd(pgd_offset_k(KASAN_SHADOW_START),
+			   KASAN_SHADOW_START, KASAN_SHADOW_END, true);
+
+	local_flush_tlb_all();
+}
+
 static void __init kasan_populate(void *start, void *end)
 {
 	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
 	unsigned long vend = PAGE_ALIGN((unsigned long)end);
 
-	kasan_populate_pgd(vaddr, vend);
+	kasan_populate_pgd(pgd_offset_k(vaddr), vaddr, vend, false);
 
 	local_flush_tlb_all();
 	memset(start, KASAN_SHADOW_INIT, end - start);
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206104657.433304-3-alexandre.ghiti%40canonical.com.
