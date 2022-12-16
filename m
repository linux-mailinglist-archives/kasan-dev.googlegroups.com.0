Return-Path: <kasan-dev+bncBDXY7I6V6AMRBXVW6KOAMGQE67TIFYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id C6E7264EEEE
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 17:22:54 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id p2-20020adfaa02000000b00241d7fb17d7sf611637wrd.5
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 08:22:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671207774; cv=pass;
        d=google.com; s=arc-20160816;
        b=WlEV9N+yuKWsoSBQRR1YP/IGi0in5RzFHvS4hSX7tm+rTN/PwBgmCWQONRIgZH8AQD
         7C9gbAqDexkhCjQDzkFoNHHhJQ6cZT1b3A14tiZ4AJPdOFmHFNcvNy1COHEIcfN2j3mg
         joOESiWJ55CTcFTwtQGCN6q5swSHD6C8Y+RUFhkZ4a9jFYtMUZ1VVc4JWKrXyBQSrOsC
         DVPKROCDGPAi+Y4rVe3VTLey2sfHKyjO2cBWWLc5k96xnXvmgsr7d/ZbZcgqBn4smnUt
         7BMJ7Z1Jk+FCJhHSngVlx5376SDVPSAUSXfWGyZ4cnW9kfLcenQGDUoGfx8icZnbzf/4
         Korw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ibdCxnQnSawhzPahYdKW3MtrcZ6pqnlfvcNWuEnjrec=;
        b=mu/XLz8Bca+RgDdKh3UM54B4iXDd3W5ChnM+3LT23v6AKFPPFPlBcCvCqOpwJT7UKk
         RLe77X2OpBvydB/Cy5be5u5CM/JQheADYbQpg0drU3D2CcFS6qy1IVqO5rlCI+cH16AQ
         Mtfqro7bceyQMXu4RHPEFRf3H8hqjb0ndxW7WyE5Cm2e/J2HUVPD8fu2KAKZ20PiWFov
         QbzBhjYp8po+NdH7PS50i5/Z5chVD9qyLYinJz0UarHqh/OIp0MTRMmsE0VZAZyqa8HG
         h4AC2+eA83mUmRVJKcp1SAvn7aSQaAfLcUiwUwu/wpDT7UYWhuKmT+wPoP/Y+11IbH31
         0HXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=hzoUHwIP;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ibdCxnQnSawhzPahYdKW3MtrcZ6pqnlfvcNWuEnjrec=;
        b=ErwhoITBbrobMV7wxGEwoFsQjO2AFOHKV8Mk8iMEldmhxMWSZMXzqZnCfjYT+K7gbg
         x/CpjGSjF6WH6WS4P5KRarxmMiwZYlbZqKPld0gjL11JfLJMERadVPpl+8ZpMX6XD2Iu
         gV0Kh/GmxMZjArl42FTiTit+U4esIdp/eWthfsXGvJ2XEW85zLoq94agSlyiNrIueiY8
         M5zss4y6KwADtwhq/F9qwJCWUnKqbvhRuLL3BBE4EuM2yZyXkwM0VJeKd5doOinACRGL
         A/dv5UlyxWjJ8jwnU5o+iuTU+jp908U28cNXzeFUKEuSSkJGqP0jntzU7ewXTAzIj1zF
         Affg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ibdCxnQnSawhzPahYdKW3MtrcZ6pqnlfvcNWuEnjrec=;
        b=e1wDK6piNNAG9uvUCqrSln5Qh37C8l26rGdzAYM/UYUwvUMczLjbwiRZZVdGRDUwF+
         DoVHoq11jmpI76Uks/aHZ92LXFPgaK5mgTPHyVnG+ugPaKm/MiCEeHeBaNkQnCnYMJEz
         OgjnW0i2xdu4oSn6PKNUwMTkn/9WHdaWUgJf456TPuy7XejpFCzuw6aBAqdSLichSoPA
         WZuGxXCz4IRPpIHJxkkPD6Z8hcxBq2YfWzBGMift5nIXjK697TOCGUE6uIByPB7Q+V8C
         4wREzfzJi3cKJbSZfco5SLu0d9sWknKijDmonJDkS6CDwBTDiA0tZhHBm/UalE3kP5Ty
         UnGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmRCZ+JaXKaI/gfY3pj7Y27eFbO9wD1s51h/COLdLCySJ+Vclz0
	F2w1rhlkqi3TUQdN9i0j5uI=
X-Google-Smtp-Source: AA0mqf6gBVrLOH0MoISoeloLbjA1cZlbKVCPSDsnJON3tFGtjVpDvEt8bzgc6EFQB1Ph+Zd18ZjJXA==
X-Received: by 2002:adf:d230:0:b0:242:52ba:30eb with SMTP id k16-20020adfd230000000b0024252ba30ebmr13644827wrh.440.1671207774297;
        Fri, 16 Dec 2022 08:22:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1f16:b0:225:6559:3374 with SMTP id
 bv22-20020a0560001f1600b0022565593374ls2347559wrb.2.-pod-prod-gmail; Fri, 16
 Dec 2022 08:22:53 -0800 (PST)
X-Received: by 2002:a05:6000:608:b0:242:2875:93c with SMTP id bn8-20020a056000060800b002422875093cmr32605699wrb.8.1671207773356;
        Fri, 16 Dec 2022 08:22:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671207773; cv=none;
        d=google.com; s=arc-20160816;
        b=rSEDrMMytV0c6VQjgfxe5CfKbY4QdAbmSGsB6/5ukDsIBu6WHaQt/pja5mv4Ed0m/w
         CngSmhtvQ8aedFKuOKinzybzGEWWbXhHBpXqub7EmGwpaRlFbO4Hk9KFkozyxqfYLyoD
         kDTmorkRhCnbr+Qnt/hLX1dbKcVFe9LZ3i7fig9svScAE+bX1q8vuSp4HjWi0vqXhYIK
         J85CT24ekhuiA/0fffRzjE0xbZzlf8KnF87Sx/qP3EAMdSDuWrQcbYxxIJthYJnh5ui6
         foPT9fw/hBbkNuGN4eblS+3vP8PujP2+dFt73jEYSpAgLBi1n9p6Jna0JSYa36f+2tPA
         5Qpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bZlFlLyFfvGOX6GgDGk2MQgjTa7NIX6OhSZPRX3tHGU=;
        b=hb4rACfCpNqxf7Kyamy5q/O5rKUTF9T6YfgaUb7q8M40SSk/mPevhgbsiiZDsdH/Dw
         8HdAhYrK/fYJs8zR+aqpZ3CCcvfybd1U7Ac0BvNxfCTJuvIwIU9Zvvzhg4r6tsqkTAHy
         giFPdzY1pmHb9L4y72reXZp2kGFteknKTrTfJexRGHgRAsv9cV37YZrwPSEbklcdkVBv
         N+t2rM8Ib9VHShbRNNyksK7VWuDPbVhPSkjSKYKzqmWoxowIs876r7g5EQU1UnaOpCM7
         ZG1RJiNyfZ167B0qAgz/q6Qc0zip7lsrXpkz6QyhqyfAplYQU8gz7GX6jNEr/TqInL2I
         UqZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=hzoUHwIP;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id a5-20020a5d4d45000000b00241d0141fbcsi123664wru.8.2022.12.16.08.22.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Dec 2022 08:22:53 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id ay40so2253051wmb.2
        for <kasan-dev@googlegroups.com>; Fri, 16 Dec 2022 08:22:53 -0800 (PST)
X-Received: by 2002:a05:600c:4e91:b0:3d1:dc6f:b1a4 with SMTP id f17-20020a05600c4e9100b003d1dc6fb1a4mr36135364wmq.5.1671207773030;
        Fri, 16 Dec 2022 08:22:53 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id h16-20020a05600c351000b003d23a3b783bsm3444035wmq.10.2022.12.16.08.22.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Dec 2022 08:22:52 -0800 (PST)
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
Subject: [PATCH 1/6] riscv: Split early and final KASAN population functions
Date: Fri, 16 Dec 2022 17:21:36 +0100
Message-Id: <20221216162141.1701255-2-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20221216162141.1701255-1-alexghiti@rivosinc.com>
References: <20221216162141.1701255-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=hzoUHwIP;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

This is a preliminary work that allows to make the code more
understandable.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/mm/kasan_init.c | 181 +++++++++++++++++++++++--------------
 1 file changed, 114 insertions(+), 67 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index a22e418dbd82..a7314ffe7d76 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -95,23 +95,13 @@ static void __init kasan_populate_pmd(pud_t *pud, unsigned long vaddr, unsigned
 }
 
 static void __init kasan_populate_pud(pgd_t *pgd,
-				      unsigned long vaddr, unsigned long end,
-				      bool early)
+				      unsigned long vaddr, unsigned long end)
 {
 	phys_addr_t phys_addr;
 	pud_t *pudp, *base_pud;
 	unsigned long next;
 
-	if (early) {
-		/*
-		 * We can't use pgd_page_vaddr here as it would return a linear
-		 * mapping address but it is not mapped yet, but when populating
-		 * early_pg_dir, we need the physical address and when populating
-		 * swapper_pg_dir, we need the kernel virtual address so use
-		 * pt_ops facility.
-		 */
-		base_pud = pt_ops.get_pud_virt(pfn_to_phys(_pgd_pfn(*pgd)));
-	} else if (pgd_none(*pgd)) {
+	if (pgd_none(*pgd)) {
 		base_pud = memblock_alloc(PTRS_PER_PUD * sizeof(pud_t), PAGE_SIZE);
 	} else {
 		base_pud = (pud_t *)pgd_page_vaddr(*pgd);
@@ -128,16 +118,10 @@ static void __init kasan_populate_pud(pgd_t *pgd,
 		next = pud_addr_end(vaddr, end);
 
 		if (pud_none(*pudp) && IS_ALIGNED(vaddr, PUD_SIZE) && (next - vaddr) >= PUD_SIZE) {
-			if (early) {
-				phys_addr = __pa(((uintptr_t)kasan_early_shadow_pmd));
-				set_pud(pudp, pfn_pud(PFN_DOWN(phys_addr), PAGE_TABLE));
+			phys_addr = memblock_phys_alloc(PUD_SIZE, PUD_SIZE);
+			if (phys_addr) {
+				set_pud(pudp, pfn_pud(PFN_DOWN(phys_addr), PAGE_KERNEL));
 				continue;
-			} else {
-				phys_addr = memblock_phys_alloc(PUD_SIZE, PUD_SIZE);
-				if (phys_addr) {
-					set_pud(pudp, pfn_pud(PFN_DOWN(phys_addr), PAGE_KERNEL));
-					continue;
-				}
 			}
 		}
 
@@ -150,32 +134,19 @@ static void __init kasan_populate_pud(pgd_t *pgd,
 	 * it entirely, memblock could allocate a page at a physical address
 	 * where KASAN is not populated yet and then we'd get a page fault.
 	 */
-	if (!early)
-		set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_pud)), PAGE_TABLE));
+	set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_pud)), PAGE_TABLE));
 }
 
 static void __init kasan_populate_p4d(pgd_t *pgd,
-				      unsigned long vaddr, unsigned long end,
-				      bool early)
+				      unsigned long vaddr, unsigned long end)
 {
 	phys_addr_t phys_addr;
 	p4d_t *p4dp, *base_p4d;
 	unsigned long next;
 
-	if (early) {
-		/*
-		 * We can't use pgd_page_vaddr here as it would return a linear
-		 * mapping address but it is not mapped yet, but when populating
-		 * early_pg_dir, we need the physical address and when populating
-		 * swapper_pg_dir, we need the kernel virtual address so use
-		 * pt_ops facility.
-		 */
-		base_p4d = pt_ops.get_p4d_virt(pfn_to_phys(_pgd_pfn(*pgd)));
-	} else {
-		base_p4d = (p4d_t *)pgd_page_vaddr(*pgd);
-		if (base_p4d == lm_alias(kasan_early_shadow_p4d))
-			base_p4d = memblock_alloc(PTRS_PER_PUD * sizeof(p4d_t), PAGE_SIZE);
-	}
+	base_p4d = (p4d_t *)pgd_page_vaddr(*pgd);
+	if (base_p4d == lm_alias(kasan_early_shadow_p4d))
+		base_p4d = memblock_alloc(PTRS_PER_PUD * sizeof(p4d_t), PAGE_SIZE);
 
 	p4dp = base_p4d + p4d_index(vaddr);
 
@@ -183,20 +154,14 @@ static void __init kasan_populate_p4d(pgd_t *pgd,
 		next = p4d_addr_end(vaddr, end);
 
 		if (p4d_none(*p4dp) && IS_ALIGNED(vaddr, P4D_SIZE) && (next - vaddr) >= P4D_SIZE) {
-			if (early) {
-				phys_addr = __pa(((uintptr_t)kasan_early_shadow_pud));
-				set_p4d(p4dp, pfn_p4d(PFN_DOWN(phys_addr), PAGE_TABLE));
+			phys_addr = memblock_phys_alloc(P4D_SIZE, P4D_SIZE);
+			if (phys_addr) {
+				set_p4d(p4dp, pfn_p4d(PFN_DOWN(phys_addr), PAGE_KERNEL));
 				continue;
-			} else {
-				phys_addr = memblock_phys_alloc(P4D_SIZE, P4D_SIZE);
-				if (phys_addr) {
-					set_p4d(p4dp, pfn_p4d(PFN_DOWN(phys_addr), PAGE_KERNEL));
-					continue;
-				}
 			}
 		}
 
-		kasan_populate_pud((pgd_t *)p4dp, vaddr, next, early);
+		kasan_populate_pud((pgd_t *)p4dp, vaddr, next);
 	} while (p4dp++, vaddr = next, vaddr != end);
 
 	/*
@@ -205,8 +170,7 @@ static void __init kasan_populate_p4d(pgd_t *pgd,
 	 * it entirely, memblock could allocate a page at a physical address
 	 * where KASAN is not populated yet and then we'd get a page fault.
 	 */
-	if (!early)
-		set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_p4d)), PAGE_TABLE));
+	set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_p4d)), PAGE_TABLE));
 }
 
 #define kasan_early_shadow_pgd_next			(pgtable_l5_enabled ?	\
@@ -214,16 +178,15 @@ static void __init kasan_populate_p4d(pgd_t *pgd,
 							(pgtable_l4_enabled ?	\
 				(uintptr_t)kasan_early_shadow_pud :		\
 				(uintptr_t)kasan_early_shadow_pmd))
-#define kasan_populate_pgd_next(pgdp, vaddr, next, early)			\
+#define kasan_populate_pgd_next(pgdp, vaddr, next)				\
 		(pgtable_l5_enabled ?						\
-		kasan_populate_p4d(pgdp, vaddr, next, early) :			\
+		kasan_populate_p4d(pgdp, vaddr, next) :				\
 		(pgtable_l4_enabled ?						\
-			kasan_populate_pud(pgdp, vaddr, next, early) :		\
+			kasan_populate_pud(pgdp, vaddr, next) :			\
 			kasan_populate_pmd((pud_t *)pgdp, vaddr, next)))
 
 static void __init kasan_populate_pgd(pgd_t *pgdp,
-				      unsigned long vaddr, unsigned long end,
-				      bool early)
+				      unsigned long vaddr, unsigned long end)
 {
 	phys_addr_t phys_addr;
 	unsigned long next;
@@ -232,11 +195,7 @@ static void __init kasan_populate_pgd(pgd_t *pgdp,
 		next = pgd_addr_end(vaddr, end);
 
 		if (IS_ALIGNED(vaddr, PGDIR_SIZE) && (next - vaddr) >= PGDIR_SIZE) {
-			if (early) {
-				phys_addr = __pa((uintptr_t)kasan_early_shadow_pgd_next);
-				set_pgd(pgdp, pfn_pgd(PFN_DOWN(phys_addr), PAGE_TABLE));
-				continue;
-			} else if (pgd_page_vaddr(*pgdp) ==
+			if (pgd_page_vaddr(*pgdp) ==
 				   (unsigned long)lm_alias(kasan_early_shadow_pgd_next)) {
 				/*
 				 * pgdp can't be none since kasan_early_init
@@ -253,7 +212,95 @@ static void __init kasan_populate_pgd(pgd_t *pgdp,
 			}
 		}
 
-		kasan_populate_pgd_next(pgdp, vaddr, next, early);
+		kasan_populate_pgd_next(pgdp, vaddr, next);
+	} while (pgdp++, vaddr = next, vaddr != end);
+}
+
+static void __init kasan_early_populate_pud(p4d_t *p4dp,
+					    unsigned long vaddr,
+					    unsigned long end)
+{
+	pud_t *pudp, *base_pud;
+	phys_addr_t phys_addr;
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
+		if (pud_none(*pudp) && IS_ALIGNED(vaddr, PUD_SIZE) &&
+		    (next - vaddr) >= PUD_SIZE) {
+			phys_addr = __pa((uintptr_t)kasan_early_shadow_pmd);
+			set_pud(pudp, pfn_pud(PFN_DOWN(phys_addr), PAGE_TABLE));
+			continue;
+		}
+
+		BUG();
+	} while (pudp++, vaddr = next, vaddr != end);
+}
+
+static void __init kasan_early_populate_p4d(pgd_t *pgdp,
+					    unsigned long vaddr,
+					    unsigned long end)
+{
+	p4d_t *p4dp, *base_p4d;
+	phys_addr_t phys_addr;
+	unsigned long next;
+
+	/*
+	 * We can't use pgd_page_vaddr here as it would return a linear
+	 * mapping address but it is not mapped yet, but when populating
+	 * early_pg_dir, we need the physical address and when populating
+	 * swapper_pg_dir, we need the kernel virtual address so use
+	 * pt_ops facility.
+	 * Note that this test is then completely equivalent to
+	 * p4dp = p4d_offset(pgdp, vaddr)
+	 */
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
+		if (p4d_none(*p4dp) && IS_ALIGNED(vaddr, P4D_SIZE) &&
+		    (next - vaddr) >= P4D_SIZE) {
+			phys_addr = __pa((uintptr_t)kasan_early_shadow_pud);
+			set_p4d(p4dp, pfn_p4d(PFN_DOWN(phys_addr), PAGE_TABLE));
+			continue;
+		}
+
+		kasan_early_populate_pud(p4dp, vaddr, next);
+	} while (p4dp++, vaddr = next, vaddr != end);
+}
+
+static void __init kasan_early_populate_pgd(pgd_t *pgdp,
+					    unsigned long vaddr,
+					    unsigned long end)
+{
+	phys_addr_t phys_addr;
+	unsigned long next;
+
+	do {
+		next = pgd_addr_end(vaddr, end);
+
+		if (pgd_none(*pgdp) && IS_ALIGNED(vaddr, PGDIR_SIZE) &&
+		    (next - vaddr) >= PGDIR_SIZE) {
+			phys_addr = __pa((uintptr_t)kasan_early_shadow_p4d);
+			set_pgd(pgdp, pfn_pgd(PFN_DOWN(phys_addr), PAGE_TABLE));
+			continue;
+		}
+
+		kasan_early_populate_p4d(pgdp, vaddr, next);
 	} while (pgdp++, vaddr = next, vaddr != end);
 }
 
@@ -290,16 +337,16 @@ asmlinkage void __init kasan_early_init(void)
 					PAGE_TABLE));
 	}
 
-	kasan_populate_pgd(early_pg_dir + pgd_index(KASAN_SHADOW_START),
-			   KASAN_SHADOW_START, KASAN_SHADOW_END, true);
+	kasan_early_populate_pgd(early_pg_dir + pgd_index(KASAN_SHADOW_START),
+				 KASAN_SHADOW_START, KASAN_SHADOW_END);
 
 	local_flush_tlb_all();
 }
 
 void __init kasan_swapper_init(void)
 {
-	kasan_populate_pgd(pgd_offset_k(KASAN_SHADOW_START),
-			   KASAN_SHADOW_START, KASAN_SHADOW_END, true);
+	kasan_early_populate_pgd(pgd_offset_k(KASAN_SHADOW_START),
+				 KASAN_SHADOW_START, KASAN_SHADOW_END);
 
 	local_flush_tlb_all();
 }
@@ -309,7 +356,7 @@ static void __init kasan_populate(void *start, void *end)
 	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
 	unsigned long vend = PAGE_ALIGN((unsigned long)end);
 
-	kasan_populate_pgd(pgd_offset_k(vaddr), vaddr, vend, false);
+	kasan_populate_pgd(pgd_offset_k(vaddr), vaddr, vend);
 
 	local_flush_tlb_all();
 	memset(start, KASAN_SHADOW_INIT, end - start);
-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221216162141.1701255-2-alexghiti%40rivosinc.com.
