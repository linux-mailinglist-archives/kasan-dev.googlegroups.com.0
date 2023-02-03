Return-Path: <kasan-dev+bncBDXY7I6V6AMRBAP36KPAMGQE4YQ4J3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AC34689144
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 08:53:39 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id s2-20020a2e1502000000b002917ff038dasf1011932ljd.7
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 23:53:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675410818; cv=pass;
        d=google.com; s=arc-20160816;
        b=OnI/igENQ8FDx2auG597l+JqXfPV0obGKZUNCzg+3ocTciSZ/hX24z4+5o+/6Lmd6V
         keCXtW2uW3jUPEII2Ho65/5+Rs3Sk0GF0YNVTrpWSYQZPxt8xPMmRAiJH9x0P6rfikru
         zTpr8tmagEjFh9cug5nTaOIJYcP//BE6LOUib/s1JPAFn/FCIk2eXroMWCvGMITXsg0a
         MZzQnLdjh2oobOhvQQ7anhROzJ+GHAIuHLOhzLPvpqHzgbcDb7UjJ5ZJBzJ0XC58ULTU
         xSjcBDjUgvE+6T+uhnE+KyhmgDy7QbRDvAjgWYlbpS7cTlVcTkIkdjFMfPdosLqfWrwk
         ryJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LA/x4tjoDrxwiKmDs4m+V8pla61c+TglU9+XyO+WvF4=;
        b=iQTKFD+R6aJLg0/YPZjuBj5pmqljSLj3hM4YjGO8qBWicgY9g9gs6ZS+wmLUP9kQUM
         86gWogf7JoGAmfGcekr5fN5+t/Ige0TU/kYfuPcRqt47G/2tLh4UN3FPGCOuZCqXSePj
         3xlGHv7sF0YqJhysh2ePN/u4n9+bPTOveJiubYuAtd5aEbtdDYM9jXPedFoVOhyn93Ro
         bCPcYHzQQUT9RByCxrbBKiS6bhIuVjeWeGdHmUsvc/ws6+UELpi1NDDlKpHf+yMEyhVA
         Flq9yDRNct0xyIxgkzL7ybLvBy0EOYmh42pLBm40XS2V77Hczln4mI2j0sgCXx85GIub
         Zbgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=I53rM8yL;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LA/x4tjoDrxwiKmDs4m+V8pla61c+TglU9+XyO+WvF4=;
        b=bq+ViIi2t0+JSyx8/9oGg/cd5WpsOAiqv2AinvkCmR4NijbvE2e5WzuRGOOLYy5PB5
         GYTVDF8o+AmKi7RbFYHZ0gNmQSSB7KYbipq/MOQXokIT1u2WKCpvzs9bSE7b6CddfgqW
         qYoJX+A04JUNE2j+oWM4DL6v0XULexkoegcY3d0OBtqgYdWOGdLvQLpuL0y8mWvWhkcW
         zJ5yc2BoveIulGXVepxhzJaqXKPKGqU/QAeq4xhEw0+HIo2R8/U9Aj7BAx+qv/7Km7f0
         OUhD2H2r0s2saw6WeDGtWlIvVyQ1DfXMJtZsxiU/QP0KLkjWKNIWs0dCvbToJI2SZroc
         rtHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LA/x4tjoDrxwiKmDs4m+V8pla61c+TglU9+XyO+WvF4=;
        b=i6QoR/MBkFnqzAtuc9lWx0yC6qehdeMe5Q14LDyRPth5Eyf3eQuJZrpSibp2KpfqfV
         1lBb3zFblYzRRYipE/5YiOV5+uWoK+yZH04uGjZI0BikXZm0inR+JUXIPdzWlySlpryr
         q4QrkZHF+fVTX+ds7z8H0Jolu9jUTWT7GX/sNun4LeHQ0pFiT1KnCF19W2+hsHakESw1
         M9dIRpBrD5jqFp1lf/P7/FSMR/R0tvihgla6dHjoFXabLEQR6oaDxtYgmAuPfC9ZWC+k
         Zc3yvir2fFSwlIPJDB4SyMfZgIlDk/lAlszSPHP1U4yKIde/7rprL0xkc939ik2TGV3t
         K25A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVv+xbWYFQ0B6mGfnDY0PGTn/OP49t5Z1irGXEmsKuotN37osPr
	BfGZw+7ZfXSOqsRsujPbRDU=
X-Google-Smtp-Source: AK7set8B29AzHUBJ4HeaD8b5l33GF99srkUTNVrHbofGGBpNcgQ0xi6M3hOwP5ijCG/xa6fcPFxACw==
X-Received: by 2002:a2e:b543:0:b0:290:5178:d96b with SMTP id a3-20020a2eb543000000b002905178d96bmr1563252ljn.158.1675410818207;
        Thu, 02 Feb 2023 23:53:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d1f:b0:4d1:8575:2d31 with SMTP id
 d31-20020a0565123d1f00b004d185752d31ls3059782lfv.0.-pod-prod-gmail; Thu, 02
 Feb 2023 23:53:36 -0800 (PST)
X-Received: by 2002:a05:6512:799:b0:4cb:4378:9c6 with SMTP id x25-20020a056512079900b004cb437809c6mr2052149lfr.23.1675410816778;
        Thu, 02 Feb 2023 23:53:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675410816; cv=none;
        d=google.com; s=arc-20160816;
        b=05Z/YE8CUr2h7cP6RoCk+mNyxmU2mpRVXAmnpJui38fUzuD10W5XQfkJpJ4BNE5IyU
         IfdO7pkJux7JSgNr8glWs9ZigoAoOqUCvU/gMaVkArrvqiH6DpcA0/kvBMklsyAL70Vl
         2LciBca2Kf25J/bl1P2Mvdl1rP2ki104Ot2njob+tXGRXhwy7TtzaLRJbhf4aPRFut/Z
         CSJxOgjDMpg6nO/qEHaulIRRTgKt1OMc631Fh6hBlt5iwo2dZa95KnOUlZX/qolxQMUp
         MzVRVJEublV964y3uP4OgQUM8aw6ZQZZDx84sEA10fFu/+r72E6nS7sid0g/v3l2SQV7
         v8qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CsDDO4uellZf0C+juEHPa8tYsGopFAarZz2ZBHCW4I4=;
        b=LSQr1CnDFVP3UbrDhas7w+B8wxtOOHn80Ho8wjiATHr7lTPDFL3Dcm38LEo/w5ktcz
         AoX+Yf9MnRlJu8g293xwKDhkzSaYvA8Pc1nevSuuGnsOIKxcc/1uMxyLE2HWWMUX6bEE
         ornqxLuO2lJdenKuJsXAln1QCHwZqh9jJaXmUmUU+xBdQaGJ66CrEknQM/KWxF/sahH3
         bHk3azvVH1yzRUhtwpY7ULtqg4ew3eADBgUx7HLCGHPKcPGfAl2yg1YTSIW38MW/kmxZ
         ff3NgtcPd2sV3mHYIM7HfZVOhNqW3FWplKYCbReelu1fNDS51nNFKmsPTfBAHWzUmg0r
         ShXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=I53rM8yL;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id y16-20020a05651c155000b0029281d83170si58643ljp.0.2023.02.02.23.53.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Feb 2023 23:53:36 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id m16-20020a05600c3b1000b003dc4050c94aso3186690wms.4
        for <kasan-dev@googlegroups.com>; Thu, 02 Feb 2023 23:53:36 -0800 (PST)
X-Received: by 2002:a05:600c:4f10:b0:3dc:58b9:83f7 with SMTP id l16-20020a05600c4f1000b003dc58b983f7mr8783023wmq.35.1675410816466;
        Thu, 02 Feb 2023 23:53:36 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id az24-20020a05600c601800b003dc4baaedd3sm7258082wmb.37.2023.02.02.23.53.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Feb 2023 23:53:36 -0800 (PST)
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
Subject: [PATCH v4 1/6] riscv: Split early and final KASAN population functions
Date: Fri,  3 Feb 2023 08:52:27 +0100
Message-Id: <20230203075232.274282-2-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230203075232.274282-1-alexghiti@rivosinc.com>
References: <20230203075232.274282-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=I53rM8yL;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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
 arch/riscv/mm/kasan_init.c | 185 +++++++++++++++++++++++--------------
 1 file changed, 116 insertions(+), 69 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index e1226709490f..2a48eba6bd08 100644
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
 		memcpy(base_pud, (void *)kasan_early_shadow_pud,
 			sizeof(pud_t) * PTRS_PER_PUD);
@@ -130,16 +120,10 @@ static void __init kasan_populate_pud(pgd_t *pgd,
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
 
@@ -152,34 +136,21 @@ static void __init kasan_populate_pud(pgd_t *pgd,
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
-		if (base_p4d == lm_alias(kasan_early_shadow_p4d)) {
-			base_p4d = memblock_alloc(PTRS_PER_PUD * sizeof(p4d_t), PAGE_SIZE);
-			memcpy(base_p4d, (void *)kasan_early_shadow_p4d,
-				sizeof(p4d_t) * PTRS_PER_P4D);
-		}
+	base_p4d = (p4d_t *)pgd_page_vaddr(*pgd);
+	if (base_p4d == lm_alias(kasan_early_shadow_p4d)) {
+		base_p4d = memblock_alloc(PTRS_PER_PUD * sizeof(p4d_t), PAGE_SIZE);
+		memcpy(base_p4d, (void *)kasan_early_shadow_p4d,
+		       sizeof(p4d_t) * PTRS_PER_P4D);
 	}
 
 	p4dp = base_p4d + p4d_index(vaddr);
@@ -188,20 +159,14 @@ static void __init kasan_populate_p4d(pgd_t *pgd,
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
@@ -210,8 +175,7 @@ static void __init kasan_populate_p4d(pgd_t *pgd,
 	 * it entirely, memblock could allocate a page at a physical address
 	 * where KASAN is not populated yet and then we'd get a page fault.
 	 */
-	if (!early)
-		set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_p4d)), PAGE_TABLE));
+	set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_p4d)), PAGE_TABLE));
 }
 
 #define kasan_early_shadow_pgd_next			(pgtable_l5_enabled ?	\
@@ -219,16 +183,15 @@ static void __init kasan_populate_p4d(pgd_t *pgd,
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
@@ -237,11 +200,7 @@ static void __init kasan_populate_pgd(pgd_t *pgdp,
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
@@ -258,7 +217,95 @@ static void __init kasan_populate_pgd(pgd_t *pgdp,
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
 
@@ -295,16 +342,16 @@ asmlinkage void __init kasan_early_init(void)
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
@@ -314,7 +361,7 @@ static void __init kasan_populate(void *start, void *end)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230203075232.274282-2-alexghiti%40rivosinc.com.
