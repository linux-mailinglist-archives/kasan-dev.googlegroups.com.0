Return-Path: <kasan-dev+bncBDXY7I6V6AMRBTOOYOPAMGQE3TPYDHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C19567AB86
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:24:46 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id d18-20020a2e3612000000b0028bd3f7b64asf2159126lja.15
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:24:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674635085; cv=pass;
        d=google.com; s=arc-20160816;
        b=xg9IsGeWQqhGPaksAoFxKyV1bAubtFl3SguQ5uy4s+yK59JPk+vhTopIGN0Op+WUOJ
         pqDXg2G9L1LfFO2UZfcdbpu66u29O7EDkcpj4BEss0EBWvXsjgArnBIoAISwxBDniSVi
         AlU8AjAiDokXP2eUK8NxiMfsvBbqo07/WzrfmIqM07nhwB50rMiPg04+gs5YzjBETaBv
         Pm38cetlKvmJSzIcno4GBBlRK8hpLPZgnclmYQ/mpnwUDaQh43t7I8lg9qzPKOrHWjp/
         lQJUSSiKWM6EuOj93nbnwO8qozEDtpFUyQAcoIqdDJ3DkrlYkvHW85GiHY5krXa0wK0l
         qe4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+SBk+fep12zj2bfOVVkLhN8y8Szi9ivCaldc126jnfs=;
        b=X3h6FqLc6l/rRCblFkPRd1dIm0cSEdWn3xBTfTym7EH551yhsYzyUH9N79Jnp+99jx
         pTsESnMuFdgx+Yug5o4RqJr2Fx5E2eyChATk0ucVqvjiIINQjrrQ9CAc/oyIhKzgAL79
         GnAHef4Owh1dZxGld8SInMao+w4gVbSFqNv2YHEqFsqV/RQxjAyntSiAjdxXR1v3IZFD
         mebc8rZmUbELBGIvC047x65zQbLvDy4XBafsFPWyQ2uxGOLPXtC69uOmYEjmrAI4f2gE
         8SGcIvOwPvkDcGEvje+Y17DhJ7R4WNyPNbcVC5TlEYFV8wlpyqzZlidfdEGBZnnWnwmA
         mDeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=dfWH2lsw;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+SBk+fep12zj2bfOVVkLhN8y8Szi9ivCaldc126jnfs=;
        b=pr0+bvp7HxP0Mj4F8kWc3p/UOOzTXpEyrhFcXw6lQSsgAuidxTslnV4LyCUQqdkRXf
         ui2QytlrYfCWCwHEIaUe+BHRwj38qilETQoHhdQR460gqNg1sp6CY3JLQ0oCUioQbPGS
         lQd3PqRygg6TY2Go4BkIQB5QglSrwLQPv8H9nuBl46CFF1vTpehmiOHaW/kXUrSENtkA
         14P58KBGmh4KSenQd0emd8HDScZswmrNZyz81BOX2FdzQx3RyPlPCLrc4nIf+9U1AqAO
         HcqJxxPc0wc3azfvF6nHPnILR4+besNmgRWSZZ4qTFkdLJ9wBoKOHoFIfkWpwnoo09yQ
         mdKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+SBk+fep12zj2bfOVVkLhN8y8Szi9ivCaldc126jnfs=;
        b=BwXJ1zV7MUfErR3uZoKlxjSPTLCztzDIbD1aIbn6MgEpkRL+MwcMxLBLes+r5LyDUI
         V6QOLN39wzbYAKGjCckXlR7dbmrgabYXwQRxsG1jDtfY7jsuUfxSJb+KGZv1XAPFahXr
         1dRATDolQS2Abk7wFcsuZ5/KY3nS5eRCjGqrhcPpFVjks8sTwJGWUsIhFjrT7RqXUFN/
         m4il/2K9d1MqBuhNiM03cWptGZygpXm9qVZCY4EAHYNPNUkflLg8w2rMk/OQ2jwb1uQ6
         K1byy7MtMM6zIFUfCUCeo7bgpAtBmr3Dcp6rL5F5yBCRQK7jrM1it/p3M2bgrRZ1QoB0
         +jVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpemJifIbHrt8I8QdE9c7BPO2awYmozADbc6+OE3lxM4dtZ5YR6
	ZyMzNkqd/veDXCD8lOrQIek=
X-Google-Smtp-Source: AMrXdXtZkFBzh81PGN5ZNsDejefNFcQvb6kfOpyAnSBdWk0LicMglY42MpfqybZwRgaVxpBE4/gPYQ==
X-Received: by 2002:a2e:8858:0:b0:27f:bc58:e679 with SMTP id z24-20020a2e8858000000b0027fbc58e679mr1557168ljj.285.1674635085691;
        Wed, 25 Jan 2023 00:24:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2082:b0:4d1:8575:2d31 with SMTP id
 t2-20020a056512208200b004d185752d31ls8931141lfr.0.-pod-prod-gmail; Wed, 25
 Jan 2023 00:24:44 -0800 (PST)
X-Received: by 2002:a05:6512:39d5:b0:4d5:8eab:cf16 with SMTP id k21-20020a05651239d500b004d58eabcf16mr8238155lfu.33.1674635084464;
        Wed, 25 Jan 2023 00:24:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674635084; cv=none;
        d=google.com; s=arc-20160816;
        b=CLnz8KWmcFWcrx2xPejuE1ExKmbMxB4Gf9uEsp1QwsVO3H5DDQK3UWSW7jPqcfGBkk
         EoowKA9dLF7j+3X2HSnNh6pAS40Cc2xqiE4cf23t+5xTpcX/ELAWxqTFBJPi0AY/F5fQ
         4TJ5n2AR173JI6UPdqrRM6SsSQjfyVJlBt7dnbsPgaOJDRi7z/HNmxvycM/morTobYEw
         EoqV2hK5UumP7jGVFZpr5EH3C/ooyTNOlYkz+gcCPiefQOs3o9H7UiaRe+Pd2vWPGKF8
         dIJIg+BevoXE+kIKRwVbAbmyJ2UyCupBozljh6dxu/whaOezCCeHi5NPUKoMeKTx561h
         9hAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CsDDO4uellZf0C+juEHPa8tYsGopFAarZz2ZBHCW4I4=;
        b=Qhe5FICUj9sEMPpl5xUU0UrBcy63qQqKqNKXXDEUFwtVRr1m8Nog8kga1Rt3B5feLj
         +CPWhfyp07KTx9GALG4kAp4sami5VHmSyrkIsqpYlyqxriEx/Yb7Lo8nhWLSZehw/EbI
         GFg5zivi7he8sijpB3FBgPFGxoUrkinF2Hi2UUixJyZ5VxCybMg17YqVtHvpkVhxnTGC
         4WPkDVz2hlgUXl2OFOhivQEg341oQATt+M+HCOJGoKxeQvwOGmUEhwqDE6FPjcOzDhgD
         +vfmiu174EvOSGQcNuADjtdlIYt6FLAGJTwoGga+vcuLkO7KdZk3amhLNIINpNrreoKu
         7txA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=dfWH2lsw;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id q26-20020a19a41a000000b004a222ff195esi244350lfc.11.2023.01.25.00.24.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 00:24:44 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id h12so12216474wrv.10
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 00:24:44 -0800 (PST)
X-Received: by 2002:a5d:4349:0:b0:2bd:e1fc:ef83 with SMTP id u9-20020a5d4349000000b002bde1fcef83mr23982267wrr.71.1674635084153;
        Wed, 25 Jan 2023 00:24:44 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id p5-20020a05600c2e8500b003db15b1fb3csm1095183wmn.13.2023.01.25.00.24.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 00:24:43 -0800 (PST)
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
Subject: [PATCH v3 1/6] riscv: Split early and final KASAN population functions
Date: Wed, 25 Jan 2023 09:23:28 +0100
Message-Id: <20230125082333.1577572-2-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230125082333.1577572-1-alexghiti@rivosinc.com>
References: <20230125082333.1577572-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=dfWH2lsw;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125082333.1577572-2-alexghiti%40rivosinc.com.
