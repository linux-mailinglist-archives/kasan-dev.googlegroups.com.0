Return-Path: <kasan-dev+bncBDXY7I6V6AMRBL52XGPAMGQEK6G7OSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id E81B76778BC
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:10:56 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id i2-20020a0565123e0200b004d5aee356dcsf2440474lfv.5
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:10:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674468656; cv=pass;
        d=google.com; s=arc-20160816;
        b=sgyes60JD5mGh9eBfWjLnXsurSSfoKOOCgI0qVKQQlnJTivrkyhrJQ0wtEVNpvZTuy
         RMfNWEtIG4rNt8lafsez079RZMcFkJQ/ycpBdDcGuwSZwrKEtlXreRiEe9ASdbFpdo7Q
         AJaaJ8jOreScMBzqwhPqQiJhgrIl1tz9YCRzghC/PGeI69zDcQjybpCsofHcD+d56rVa
         Xv0qVdL0i4Z+XpmcqxgaQeFroYWd/Ie4Yo8X76NAKuE3iXpUCXF6PF+Ke5gAlNUHEWzL
         XjlAKpSTeAUDvKNjGGp9bZKVWs+U09HouZWbDS7i6d+ae7rzq2ncwPXcnK3beMYh17j8
         7Ivg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=53n0746veP51pXmsIptNb+RSq0NTTLbqYsfmGkBo6B0=;
        b=Y6uzOMTV3xOiZDnvAnw+UaZvQRbmvByHqxm0rWyahr2WqpMXhlBJJL4GUwWZdbKTFx
         2ef9gafWZ1VdUtXm1UbXgsmdha4R4zU5LYLtTCwJ7ttjkr4eZdrZcZ7AmQIh14S4cL/I
         BQoBiospxNzl1MKw4C8K8nF2oCRxFXOhlSbA9lX/RTmw6lY1Tf7I1jT6u1qhmDmjVRSE
         Yi9yMp+NwlkMcdUvicXQ0IUYN8n/9k3vm9ZXX1XbSe4j5KV15WLLKmf6DLJxm+cQ8bVP
         omoHDS1DZS0JrLF0pZ7dNn2/eapZ44d/7fU0+3bGiU/dxEBKP3v9PctOjJM49kfA5Yuk
         K9lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=oQYgkSxo;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=53n0746veP51pXmsIptNb+RSq0NTTLbqYsfmGkBo6B0=;
        b=FdHybkmFLDwvpfLbHeUM8CW6uUbsSBMWKjFyfj6sRXD0O+OsS2feHwQIwXAMyw0nTt
         HOp8fTqgOZcS1Prx+TCxVRXxXM1KsKivnSPlSZ39ZkM/LAhmaNPGicKvVB1OYoOV4nxq
         KWFvSthggl0QWbUDBdIhhypzO2C0IrQGg/UxcNgJaKh0Eg76idR+CQzOiclcee083Grm
         mpjjOoOns/OQq5QNMWzAam2z5XYOmQH0LKFUFSzbVe4RDQ9a0ZAgeM1ciggbK0SbvsKw
         uWNMZXAOo3eQY4MfvOM4PAeM9SHOX1tUGB/1N9gzOzVVB8NXwXpBucRqPGLYKcvd9uln
         I3OA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=53n0746veP51pXmsIptNb+RSq0NTTLbqYsfmGkBo6B0=;
        b=XuB8TOsy2CZBG+X0SstYcDQvto1pmf8mipvAwC/jy17QooRrxZe6jGxq/CqUBFGaqe
         UfWhg9Jk3rE1Vm6kc1RDbnFLpAON1USRPtrYXo1FC5KGxHcJj50/eKZSlo6gfd8i6CQD
         S4xdiqGmd+N47Hx9rShN0kkIPVAm9Ryt5rEZdB9d+AWTx4vy8JNQOzy92AigxwpU1h7G
         NXnCMTRKmFdXdaTrVzh24waFrBKoc3R0EM7cc1eg4sdth18zofSLZgMsZmSDr+JqPbZZ
         xUeMsumWCQcdYHFm+ztT+T1xaQhYbv42koRBtd7cpK5i8cEExErQFpKOWtLuDUaAJCZE
         aWbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqTwK2OfLKLkh1CDRUNKra4t7pCyXSXbZcKmc/dC/SR45YxOMCi
	VGlSJuWzuNuusCJdSz3CjwE=
X-Google-Smtp-Source: AMrXdXubB9V7Bqqxo6PYnR7aBwg7qGyZuKR2zLS4zQDNsyx7AnzgCtHXq/hBXEtRoyEKJcWkflokYQ==
X-Received: by 2002:a2e:8657:0:b0:285:e489:33c6 with SMTP id i23-20020a2e8657000000b00285e48933c6mr1718380ljj.158.1674468656220;
        Mon, 23 Jan 2023 02:10:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2082:b0:4d1:8575:2d31 with SMTP id
 t2-20020a056512208200b004d185752d31ls4095086lfr.0.-pod-prod-gmail; Mon, 23
 Jan 2023 02:10:55 -0800 (PST)
X-Received: by 2002:a05:6512:3ca0:b0:4a4:68b8:f4f0 with SMTP id h32-20020a0565123ca000b004a468b8f4f0mr8670361lfv.54.1674468655068;
        Mon, 23 Jan 2023 02:10:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674468655; cv=none;
        d=google.com; s=arc-20160816;
        b=Ut6WCvbr5zYEMLYcrh3jkUQkHaJ4QiNBd9aoMvRbTvNaZMn4vrfNzIs35EQkJ6Vln+
         faxL5EhfFYO7tuJCKr4LJVZ6eDdXepMURsj1aQp9FYV8ypdeA6/CqafA/PtMVFxUDwEB
         A7OrMiVMexV+iLFPuaADongO7WI7izx+nk26Jvh7ck4vH3S4Hd2V6jOn9zUWfI5pKVrz
         mQl5BAnUb4wqTDcjB/psO2W846YpbwehmpjRyafqp/xnUv66nMXC+eHLxTaSOVmZFg+L
         kzB9mzNNryUfs2xZjDRX2b9nli/B6Y3wpkivBec3afSbQFdibA1izKmixt5GZvHApgW0
         7fEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=J+Fj80rLiudnEryzZYSTURSW9/j8riSTbxetIYC+pOE=;
        b=zVZMIN8xs9u85ReqzC8OGNJ0n/C5hUL2qS4OGukQ1f/uRP9wdvoPf9e8sPAMl1Y3rD
         QhZbV2vX4hSWEJmV2G9zv7M7GdPDyNAhlsyhgBukxCES97psENTNT86CaijUyu+w5i0D
         IXbT4hceI5TwdDkk5q0KmxGFUle4RwCCkZEEDl81gpJM2PXIg203n6HmUE8JMQBA/zoG
         npeUZbiHxmoBz8p6Dszqa3Zi45+jcxFMJ1jMqGVMrgPa1WDlspUZcGgUskxQNoQADCeT
         5ELaG+D7FCoe4UtCQqisvURb41xYH5C+ojJKB7l7YAVohNvtJ6RpokYKp8jIjTCtA+BF
         SALw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=oQYgkSxo;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id o10-20020a05651205ca00b004ce3ceb0e80si1410391lfo.5.2023.01.23.02.10.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:10:55 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id q10-20020a1cf30a000000b003db0edfdb74so4044787wmq.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:10:55 -0800 (PST)
X-Received: by 2002:a05:600c:4f08:b0:3db:9e3:3bf1 with SMTP id l8-20020a05600c4f0800b003db09e33bf1mr22181752wmq.31.1674468654715;
        Mon, 23 Jan 2023 02:10:54 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id p7-20020a05600c468700b003db0bb81b6asm10803053wmo.1.2023.01.23.02.10.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Jan 2023 02:10:54 -0800 (PST)
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
Subject: [PATCH v2 1/6] riscv: Split early and final KASAN population functions
Date: Mon, 23 Jan 2023 11:09:46 +0100
Message-Id: <20230123100951.810807-2-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230123100951.810807-1-alexghiti@rivosinc.com>
References: <20230123100951.810807-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=oQYgkSxo;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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
 arch/riscv/mm/kasan_init.c | 187 +++++++++++++++++++++++--------------
 1 file changed, 117 insertions(+), 70 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index e1226709490f..9a5211ca8368 100644
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
 
@@ -152,35 +136,22 @@ static void __init kasan_populate_pud(pgd_t *pgd,
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
-	}
+	base_p4d = (p4d_t *)pgd_page_vaddr(*pgd);
+	if (base_p4d == lm_alias(kasan_early_shadow_p4d)) {
+		base_p4d = memblock_alloc(PTRS_PER_PUD * sizeof(p4d_t), PAGE_SIZE);
+        memcpy(base_p4d, (void *)kasan_early_shadow_p4d,
+                sizeof(p4d_t) * PTRS_PER_P4D);
+    }
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230123100951.810807-2-alexghiti%40rivosinc.com.
