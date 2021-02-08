Return-Path: <kasan-dev+bncBC447XVYUEMRBD5EQ2AQMGQELOL6BFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 5531A313F0B
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 20:33:36 +0100 (CET)
Received: by mail-ej1-x638.google.com with SMTP id m4sf13053862ejc.14
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 11:33:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612812816; cv=pass;
        d=google.com; s=arc-20160816;
        b=eCongrs1+iLGWMoss1nPvYjD34xCt2tsQqnrRanPv1zY/0Hoc9BApTw8skj07sxK8e
         cdW++C68+jBgSjFFN4ru9h6CZJM7BlhGfDuU8a3Thnpip8xTRLCQdfcLAtlIEuhBPxY3
         0BjOwiCoqo/cKgBEaXFbvF/RBuo+ALmelCcLlg1s0OUapWOAn/WsxSGce4VASeAEs8mv
         DpG7lwBf6paLOGi8XISrNX8jdyz9maRFoYtjk9TA40/wUFQ3/4t2S0TjRr5glSrGi53l
         O83ZxhXAwsf3Cl44NNEQxHB66OXyBWwPuRwtD6bfUN860HePhPKTMHb8YcTq7T0EcpO8
         GPfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QwgxpJGvwkXKEjuwnOY5E9vNhZX+TFsiLNeDFAlWID4=;
        b=0OOIvNG57NM/u2GDXFm03De1XU7qE40ADU7ZnGonrBt1kajyzHz2Vo0I6rT2FWlJIu
         mVpgt80P8C2cFIgBcHg9FfmgVOds/SnRtEOd2bLftbH8IEHC0fMJtdTwqCIpA1LfOxzX
         T5r7WyzPq/dVSFBkOt2mtyqIIS0qDIjyGUbgfJEPeolgYYYHqXscW33tuCmSGW1iJSDf
         lXLHEDziL5DlUpWJ/6WQLI0K+5uQHvBQLE3lXqH2QdDwGFrfk+rWwpHD5pP0cKnahEGK
         cAfL2Ff2Aog3DzxiJ+q1u2kAaC0cZMbGQB/Wo3f/pczWtTbuWRx030T7kozUN6f/w2ZB
         z93A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QwgxpJGvwkXKEjuwnOY5E9vNhZX+TFsiLNeDFAlWID4=;
        b=AmlyjV5m8Y47xaMsA/5Ui8GYrbtHEDBE6mtXJEKrEl8NtLE9w+0NA9RXhe8ShIxSDB
         m/1GtLKuNRHf5yPkwJcP/1bBPdPTtqZD5cpeAzuExzUunkCFTvQaIrI7QG4SaGrxm76j
         cW3/lX9wV3nZ3GCpCYwFYSde6Bt0SChB4KqSiz3lkqiyM/YjNFcW1/7Sw7cmTfRKmiX9
         3ppnroBfgyt0p5yNhBCPo7TZVDl84DCT6lZ8sYUHdByxhbVrXqFIzcrRMFZNrwR39P/k
         h31h77fL57s1URz1J0WUcyZx0SHKW3X+c2qE25lxcE32gVVhqj9NOfQGl6gpd1kAN1Cy
         UTxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QwgxpJGvwkXKEjuwnOY5E9vNhZX+TFsiLNeDFAlWID4=;
        b=t3UM4DXo8gi2OZIVvy78M2/F2l7MyaCaVDoMHA3e1DcPboYgr0cZ9SePtkxKU0VeOL
         RO5wE3T7ScjvoqODbUHLOI7y5qg6hH3obyrVUHfJn+KXth14sSPK7Zehz+D9PTwcGRK+
         ZKLyFKkNsPu8ZOpVZ/1YXBT8I9SrHeBv7ZCqKboMqwyyn+liQ0PYsXcrb2XC4IZun3oY
         rxmiSONgQS8GUV/EUXbSr+SWkgcfnlnfd3XeMG9n+zb+J+tBRKOiXOwKmlYTH+8VF3hc
         evKVTwSxspEERGTPKG55OWfIzhAJX/f7XaO+33FSetzdcS4mhw2LAYdhCyXQARvy8nHT
         NT5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cR9xBXQdTjshKqvDtLjTPRcwlgF4ySMdF9HekfGVBnBNXYXnI
	S0OWI3saMpFCWnsy8j5RdUs=
X-Google-Smtp-Source: ABdhPJwTZmGPQZkb21dFnhH/eBHjB3FhzZ+VnExRsg9d831AQuaSd5ju8XpG4ikXcqiotheWExe/ug==
X-Received: by 2002:a50:ec8f:: with SMTP id e15mr18735912edr.79.1612812816090;
        Mon, 08 Feb 2021 11:33:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1cc7:: with SMTP id i7ls7286027ejh.9.gmail; Mon, 08
 Feb 2021 11:33:35 -0800 (PST)
X-Received: by 2002:a17:906:9a06:: with SMTP id ai6mr18636501ejc.463.1612812815336;
        Mon, 08 Feb 2021 11:33:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612812815; cv=none;
        d=google.com; s=arc-20160816;
        b=bH0NtOOejdqa4w7rNQ+EVl9uX2tBI2IjxSpnufl9cYQ3mBkSRQhPuZzMdv8r9pnqH9
         zw7nXkmw9mtH1Js1Me+0cPejScGvrfTtExEzYcL+Rt9fjUIhcpiM60IUSLdCl0T2NMAS
         BlNvnf/FJr+VAUYuQ79bbLbjOrdDCNVZJc87jysyHLOOorAVxPscpjYMkUQvpUQDTewV
         kdX6MKwaBYkwulqMaaHTr4gYtSnVeycO0hcCPNemwKcH4Orrfpnx1dm2XmNy7K8VLHYU
         EYhLxZp6CVIzLv+Uwt58ms8wnnTKyp9bhU1pPYmLxV1UkS4C2AgLIRdDcUKmFLZAx+0r
         1htQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=7cuSSFVmzAI8j2LCy7Kkhe8lqAWlu8EgJFbOmPIOHNY=;
        b=x3xJttpTzLybOA3gDBRo6yd9Stc/WmPw93xGUtgwqitnmaRyWjCFChwmYHgp/UwhMU
         QXw+smQYvnk+aaKxeJoNG+z3BAzdmZQreQGTZKtlSaagbuSpJzcbcq4hnUhFhxfm9Qx6
         jGdVmgcj5MejAfz8aUVZ+US32/Wr4F8IuOotdNeWp2dJPQ61hHT6/u+o59HH57juGkAb
         w2hiCZnoUAzYr4isVNp1Ngem/S09sJUqjH7cXaScbiDLZleF9wFAAOrNdvmQ9Ad1gzDm
         BYEsiNcQg19glNWI1m0q4XDg49XhbRsbP3C4/GGPVVKvnXq239x4pNnMZoTpijBQOS1i
         GqiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id a15si1055260edn.0.2021.02.08.11.33.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 08 Feb 2021 11:33:35 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.193;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay1-d.mail.gandi.net (Postfix) with ESMTPSA id D3BB0240005;
	Mon,  8 Feb 2021 19:33:31 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH 3/4] riscv: Improve kasan population function
Date: Mon,  8 Feb 2021 14:30:16 -0500
Message-Id: <20210208193017.30904-4-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210208193017.30904-1-alex@ghiti.fr>
References: <20210208193017.30904-1-alex@ghiti.fr>
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.193 is neither permitted nor denied by best guess
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

Current population code populates a whole page table without taking care
of what could have been already allocated and without taking into account
possible index in page table, assuming the virtual address to map is always
aligned on the page table size, which, for example, won't be the case when
the kernel will get pushed to the end of the address space.

Address those problems by rewriting the kasan population function,
splitting it into subfunctions for each different page table level.

Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
---
 arch/riscv/mm/kasan_init.c | 91 ++++++++++++++++++++++++++------------
 1 file changed, 63 insertions(+), 28 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 7bbe09416a2e..b7d4d9abd144 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -47,37 +47,72 @@ asmlinkage void __init kasan_early_init(void)
 	local_flush_tlb_all();
 }
 
-static void __init populate(void *start, void *end)
+static void kasan_populate_pte(pmd_t *pmd, unsigned long vaddr, unsigned long end)
+{
+	phys_addr_t phys_addr;
+	pte_t *ptep, *base_pte;
+
+	if (pmd_none(*pmd))
+		base_pte = memblock_alloc(PTRS_PER_PTE * sizeof(pte_t), PAGE_SIZE);
+	else
+		base_pte = (pte_t *)pmd_page_vaddr(*pmd);
+
+	ptep = base_pte + pte_index(vaddr);
+
+	do {
+		if (pte_none(*ptep)) {
+			phys_addr = memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
+			set_pte(ptep, pfn_pte(PFN_DOWN(phys_addr), PAGE_KERNEL));
+		}
+	} while (ptep++, vaddr += PAGE_SIZE, vaddr != end);
+
+	set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(base_pte)), PAGE_TABLE));
+}
+
+static void kasan_populate_pmd(pgd_t *pgd, unsigned long vaddr, unsigned long end)
+{
+	phys_addr_t phys_addr;
+	pmd_t *pmdp, *base_pmd;
+	unsigned long next;
+
+	base_pmd = (pmd_t *)pgd_page_vaddr(*pgd);
+	if (base_pmd == lm_alias(kasan_early_shadow_pmd))
+		base_pmd = memblock_alloc(PTRS_PER_PMD * sizeof(pmd_t), PAGE_SIZE);
+
+	pmdp = base_pmd + pmd_index(vaddr);
+
+	do {
+		next = pmd_addr_end(vaddr, end);
+		kasan_populate_pte(pmdp, vaddr, next);
+	} while (pmdp++, vaddr = next, vaddr != end);
+
+	/*
+	 * Wait for the whole PGD to be populated before setting the PGD in
+	 * the page table, otherwise, if we did set the PGD before populating
+	 * it entirely, memblock could allocate a page at a physical address
+	 * where KASAN is not populated yet and then we'd get a page fault.
+	 */
+	set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_pmd)), PAGE_TABLE));
+}
+
+static void kasan_populate_pgd(unsigned long vaddr, unsigned long end)
+{
+	phys_addr_t phys_addr;
+	pgd_t *pgdp = pgd_offset_k(vaddr);
+	unsigned long next;
+
+	do {
+		next = pgd_addr_end(vaddr, end);
+		kasan_populate_pmd(pgdp, vaddr, next);
+	} while (pgdp++, vaddr = next, vaddr != end);
+}
+
+static void __init kasan_populate(void *start, void *end)
 {
-	unsigned long i, offset;
 	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
 	unsigned long vend = PAGE_ALIGN((unsigned long)end);
-	unsigned long n_pages = (vend - vaddr) / PAGE_SIZE;
-	unsigned long n_ptes =
-	    ((n_pages + PTRS_PER_PTE) & -PTRS_PER_PTE) / PTRS_PER_PTE;
-	unsigned long n_pmds =
-	    ((n_ptes + PTRS_PER_PMD) & -PTRS_PER_PMD) / PTRS_PER_PMD;
-
-	pte_t *pte =
-	    memblock_alloc(n_ptes * PTRS_PER_PTE * sizeof(pte_t), PAGE_SIZE);
-	pmd_t *pmd =
-	    memblock_alloc(n_pmds * PTRS_PER_PMD * sizeof(pmd_t), PAGE_SIZE);
-	pgd_t *pgd = pgd_offset_k(vaddr);
-
-	for (i = 0; i < n_pages; i++) {
-		phys_addr_t phys = memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
-		set_pte(&pte[i], pfn_pte(PHYS_PFN(phys), PAGE_KERNEL));
-	}
-
-	for (i = 0, offset = 0; i < n_ptes; i++, offset += PTRS_PER_PTE)
-		set_pmd(&pmd[i],
-			pfn_pmd(PFN_DOWN(__pa(&pte[offset])),
-				__pgprot(_PAGE_TABLE)));
 
-	for (i = 0, offset = 0; i < n_pmds; i++, offset += PTRS_PER_PMD)
-		set_pgd(&pgd[i],
-			pfn_pgd(PFN_DOWN(__pa(&pmd[offset])),
-				__pgprot(_PAGE_TABLE)));
+	kasan_populate_pgd(vaddr, vend);
 
 	local_flush_tlb_all();
 	memset(start, KASAN_SHADOW_INIT, end - start);
@@ -99,7 +134,7 @@ void __init kasan_init(void)
 		if (start >= end)
 			break;
 
-		populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
+		kasan_populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
 	};
 
 	for (i = 0; i < PTRS_PER_PTE; i++)
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208193017.30904-4-alex%40ghiti.fr.
