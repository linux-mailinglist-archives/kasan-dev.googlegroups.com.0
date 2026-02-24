Return-Path: <kasan-dev+bncBDGZVRMH6UCRBWPG6TGAMGQET6NPVMY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id kJZ3EVwznWlINQQAu9opvQ
	(envelope-from <kasan-dev+bncBDGZVRMH6UCRBWPG6TGAMGQET6NPVMY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 06:13:00 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D4437181D01
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 06:12:59 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-89493622b50sf72095656d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Feb 2026 21:12:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771909978; cv=pass;
        d=google.com; s=arc-20240605;
        b=RY/CFRXipGVPgYQsZECy16w8HdhaWzpvQphvpNA/MvMi9bUbthRjSgGhpg9JRnCJZX
         M8jj7NIGDylrmFUIiPtZh/JvXWozmtfSB1enlmGMJFsRBNG5y0HiJWm5fwN35KnFd1T3
         l1UcDWhc0PdQhnrJjRx3c+YIAKMXC7HmIPefwER9T4RdGbmVfszLycnvdcbz98Wux088
         J/CcerZnGcgsfKHwNafFRxQTztCZjK1shJEyg+MVLU4kqkG4R0BfJTSdThTwGEJ87QqG
         21nQ30iIFPJV4KEa3v8DBSwVfTSzDQqdZJW50aSNBEbhMMjnaiVOTy2NTWaDL4XDjc8B
         bTcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bw+/mkuHHNqchHmGLYxJ4Hpc9ImLCVrjD77bzD9sks4=;
        fh=VOAHZPNG0FHssTmBp7Bvterh2dK3QE783oiB7gOk2N0=;
        b=LFMx2aOyr/PXYrgL25JwbijUb3EmIYlre+DocEoixnpTTDxc7ZIVNp1+jc3Kq6asyo
         bfnVz6/i4RhkV4krwJQURVqbraqrJKlMeG4RPT/muBYxlVi/Va0plWz7dO4+mAUxa8hd
         O/IPHtj1h7iJHBXxlCizKqYdNYZIXfvBXiRO8GxW9iFK809YXr70Uo9Il+uuLWwucI3o
         gOs8hLELb+DIGaMbiHGigv1gJEG2MKie12Grjzg9ZrcfVkqREFomdSc57klYmPJfvvJ9
         NUyuJgtgYcLPZwDTuwS2BMh8K+F7iJ75usrMf2UUeA+XO5DK1G4BtKmKg5NVzz0urukG
         vd8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771909978; x=1772514778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bw+/mkuHHNqchHmGLYxJ4Hpc9ImLCVrjD77bzD9sks4=;
        b=vVNgNYi438aQX3eA6MVSehJHrG0j+UvNURwmEPYfvtovziHrGlK4/uMUL4dkEb2cga
         IthsYU4f44AcwtIo6c5YBKLWcNti0MdDaOf3ZQzt8l0JbdBzrqHyKbp8FRGzBeeQ0xax
         7gkop7fNrRXhb3Zhg4wFeTav0U/ZVaNYaNaK1v2PTLkCDna0OLYDGkvI2M8cg7qYkUK7
         gS9ml7rWgn2wPTrJuYjAuYFyNas688njDF5UGb82+AJHlNlFAfQwgWNKiuCmWM9a7Kw5
         GslqJYHCPl4Ct8pKZN23R6/8ftiDfUWTg7Lfmdz5/g8R70mFsNZ+JdjVZzeSQLQLJNmF
         Brfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771909978; x=1772514778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bw+/mkuHHNqchHmGLYxJ4Hpc9ImLCVrjD77bzD9sks4=;
        b=eblel0mIAHZo3UfSMHL0kuAfi863g9XtpdmIOvXY5Vd2H1KOtPSbyH+S0zCbM5/7uo
         l90Cejx7DzHwJbQvbk5N+gNznqZZTTo/ev6V3ynyuKjgW1E9w1Hok7Vq6eLCwjBJ66J3
         q6YmuJJ9tDbyaC16x5bAmBBw0A7HFJcRCtdrhwE7fXlrfo+QwLE7PPGlV5S3h+XN/wS2
         yULITL//Q1f+So44XCJkxF80M+RbQ+y2ud9isO4mhPRdsMhLo1uAIhDS9fkQqbRQE4Lb
         HndYHcDm1L5n11uAx6LDD9gN4IRWjm60Vd6A6ekQ1hnG/SdbAw2nzfcLCKPH94KgIJYK
         0gtg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWp6inLC9ULmbkULCwCMQRF42ew/R6cLoIyGmbPjuoCmqWLYTPE+w4/qNz7Z8ez5zuVmI4NQQ==@lfdr.de
X-Gm-Message-State: AOJu0YzltG1qyDW8jejlmyrxNjiO9cHzUS11QeK4JaWjU4HAFiCzjgOQ
	3RgDshFiZJm29pdN2ZAf6rZ7wdh7GAgK+R7a5LjeKuYKvuDaEuS7+qKH
X-Received: by 2002:a05:6214:482:b0:897:235:f058 with SMTP id 6a1803df08f44-89979c715c0mr150492686d6.17.1771909978028;
        Mon, 23 Feb 2026 21:12:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E81647daxRBJtGT7GCaacy6Cucu3WfG3p/7eL+h2gNXw=="
Received: by 2002:a05:6214:cc5:b0:896:f372:8c82 with SMTP id
 6a1803df08f44-89729e1e47bls200383976d6.2.-pod-prod-08-us; Mon, 23 Feb 2026
 21:12:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWrAA/I/wb+z3ydovqgSs8MhifYIjIKGQ/6KB1gjBUF6xBtODg+ENTG7uzZDaQATryeT+gWJCC/SgY=@googlegroups.com
X-Received: by 2002:a05:6122:130f:b0:567:d87:e152 with SMTP id 71dfb90a1353d-568e4901e86mr3969401e0c.18.1771909977166;
        Mon, 23 Feb 2026 21:12:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771909977; cv=none;
        d=google.com; s=arc-20240605;
        b=CAchzuRu0fNE3XnVEEHCXZi3lmuPs3OuAxIXnjhsSFZsGdYQ27z3ZtBkujuCiQ1r8L
         b7yf/yzr9J4ikW/7irqFch2NNUq7UTzjFsLJdx64aKRWUQYcRBKut/C0/LRq049pY4Q5
         uzUleINgItr4jl1CA2gyBetgs16GuJfhuOkNAT6c10tuug+A4FDX4hxnI+wwM57/TarW
         uwDTkVrjofLgBdBxN1rhqmzuT0LRiq3/ZYYDvICl7ULqrI6uu058lk5LbrCfxGxLkzDw
         Rwlr7qrxVF/XXKYMB1F+Zbd+4YJe2sU7v++p8DMYhbkGmOdR91IHbRK/A3mBT/li73md
         4v1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=0icXPR7E2F4bmO9VMv9i3sMLenBSnQY81H2T56lZaYw=;
        fh=/5PcxhpYFRn2Yp66x6S75u1IlAhfwysKHKXRRS1r5Qc=;
        b=cLA7JJ7gZ3xvJzlByvD+kPKY2A2RvQ9jGzJtRXTTFwVQlkUHLta9wAnUFyOnev7+7m
         HlDg7fcUa72g5p36uhsu9dLkGV9WT6mKm4P664GD1xlPSlYizdimV7TxcN5xhL0I/45w
         pmSm/Q+3emCx03jBLGr8JTrrM068kZ4EKQR505RKl5QTgABoVyEK6bs2HsAV75qRepVY
         OhAFAapU/PSr9T4hXgTEdGHnEDEOYDBWRlqJGBET391i6spe0OXFrKA5FrruhcEbQ186
         FvIjjbvflkO1zOl5f+TjrYi6xJUlcHwUbewp5rCVKyHdkevde6v8LUA7UHTS2Kbmo57O
         A0iA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 71dfb90a1353d-568e58a7e0dsi307821e0c.4.2026.02.23.21.12.56
        for <kasan-dev@googlegroups.com>;
        Mon, 23 Feb 2026 21:12:56 -0800 (PST)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CA9A7497;
	Mon, 23 Feb 2026 21:12:49 -0800 (PST)
Received: from a085714.blr.arm.com (a085714.arm.com [10.164.18.87])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id A2A183F7BD;
	Mon, 23 Feb 2026 21:12:51 -0800 (PST)
From: Anshuman Khandual <anshuman.khandual@arm.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Anshuman Khandual <anshuman.khandual@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Ryan Roberts <ryan.roberts@arm.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@kernel.org>,
	Mike Rapoport <rppt@kernel.org>,
	Linu Cherian <linu.cherian@arm.com>,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Subject: [RFC V1 06/16] arm64/mm: Convert READ_ONCE() as pudp_get() while accessing PUD
Date: Tue, 24 Feb 2026 10:41:43 +0530
Message-ID: <20260224051153.3150613-7-anshuman.khandual@arm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20260224051153.3150613-1-anshuman.khandual@arm.com>
References: <20260224051153.3150613-1-anshuman.khandual@arm.com>
MIME-Version: 1.0
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.61 / 15.00];
	MID_CONTAINS_FROM(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[arm.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBDGZVRMH6UCRBWPG6TGAMGQET6NPVMY];
	RCPT_COUNT_TWELVE(0.00)[14];
	FROM_HAS_DN(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[anshuman.khandual@arm.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[infradead.org:email,arm.com:mid,arm.com:email,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: D4437181D01
X-Rspamd-Action: no action

Convert all READ_ONCE() based PUD accesses as pudp_get() instead which will
support both D64 and D128 translation regime going forward.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Ryan Roberts <ryan.roberts@arm.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: linux-arm-kernel@lists.infradead.org
Cc: linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com
Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
---
 arch/arm64/include/asm/pgtable.h |  3 ++-
 arch/arm64/mm/fault.c            |  2 +-
 arch/arm64/mm/fixmap.c           |  2 +-
 arch/arm64/mm/hugetlbpage.c      |  4 ++--
 arch/arm64/mm/kasan_init.c       |  4 ++--
 arch/arm64/mm/mmu.c              | 20 ++++++++++----------
 arch/arm64/mm/pageattr.c         |  2 +-
 arch/arm64/mm/trans_pgd.c        |  4 ++--
 8 files changed, 21 insertions(+), 20 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index 4b5bc2c09bf2..93d06b5de34b 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -913,7 +913,8 @@ static inline pmd_t *pud_pgtable(pud_t pud)
 }
 
 /* Find an entry in the second-level page table. */
-#define pmd_offset_phys(dir, addr)	(pud_page_paddr(READ_ONCE(*(dir))) + pmd_index(addr) * sizeof(pmd_t))
+#define pmd_offset_phys(dir, addr)	(pud_page_paddr(pudp_get(dir)) + \
+					 pmd_index(addr) * sizeof(pmd_t))
 
 #define pmd_set_fixmap(addr)		((pmd_t *)set_fixmap_offset(FIX_PMD, addr))
 #define pmd_set_fixmap_offset(pud, addr)	pmd_set_fixmap(pmd_offset_phys(pud, addr))
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 1389ba26ec74..64836bc14798 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -171,7 +171,7 @@ static void show_pte(unsigned long addr)
 			break;
 
 		pudp = pud_offset(p4dp, addr);
-		pud = READ_ONCE(*pudp);
+		pud = pudp_get(pudp);
 		pr_cont(", pud=%016llx", pud_val(pud));
 		if (pud_none(pud) || pud_bad(pud))
 			break;
diff --git a/arch/arm64/mm/fixmap.c b/arch/arm64/mm/fixmap.c
index 7a4bbcb39094..dd58af6561e0 100644
--- a/arch/arm64/mm/fixmap.c
+++ b/arch/arm64/mm/fixmap.c
@@ -56,7 +56,7 @@ static void __init early_fixmap_init_pmd(pud_t *pudp, unsigned long addr,
 					 unsigned long end)
 {
 	unsigned long next;
-	pud_t pud = READ_ONCE(*pudp);
+	pud_t pud = pudp_get(pudp);
 	pmd_t *pmdp;
 
 	if (pud_none(pud))
diff --git a/arch/arm64/mm/hugetlbpage.c b/arch/arm64/mm/hugetlbpage.c
index 6117aca2bac7..b229c05bfbb6 100644
--- a/arch/arm64/mm/hugetlbpage.c
+++ b/arch/arm64/mm/hugetlbpage.c
@@ -262,7 +262,7 @@ pte_t *huge_pte_alloc(struct mm_struct *mm, struct vm_area_struct *vma,
 		WARN_ON(addr & (sz - 1));
 		ptep = pte_alloc_huge(mm, pmdp, addr);
 	} else if (sz == PMD_SIZE) {
-		if (want_pmd_share(vma, addr) && pud_none(READ_ONCE(*pudp)))
+		if (want_pmd_share(vma, addr) && pud_none(pudp_get(pudp)))
 			ptep = huge_pmd_share(mm, vma, addr, pudp);
 		else
 			ptep = (pte_t *)pmd_alloc(mm, pudp, addr);
@@ -292,7 +292,7 @@ pte_t *huge_pte_offset(struct mm_struct *mm,
 		return NULL;
 
 	pudp = pud_offset(p4dp, addr);
-	pud = READ_ONCE(*pudp);
+	pud = pudp_get(pudp);
 	if (sz != PUD_SIZE && pud_none(pud))
 		return NULL;
 	/* hugepage or swap? */
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 709e8ad15603..19492ef5940a 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -76,7 +76,7 @@ static pte_t *__init kasan_pte_offset(pmd_t *pmdp, unsigned long addr, int node,
 static pmd_t *__init kasan_pmd_offset(pud_t *pudp, unsigned long addr, int node,
 				      bool early)
 {
-	if (pud_none(READ_ONCE(*pudp))) {
+	if (pud_none(pudp_get(pudp))) {
 		phys_addr_t pmd_phys = early ?
 				__pa_symbol(kasan_early_shadow_pmd)
 					: kasan_alloc_zeroed_page(node);
@@ -150,7 +150,7 @@ static void __init kasan_pud_populate(p4d_t *p4dp, unsigned long addr,
 	do {
 		next = pud_addr_end(addr, end);
 		kasan_pmd_populate(pudp, addr, next, node, early);
-	} while (pudp++, addr = next, addr != end && pud_none(READ_ONCE(*pudp)));
+	} while (pudp++, addr = next, addr != end && pud_none(pudp_get(pudp)));
 }
 
 static void __init kasan_p4d_populate(pgd_t *pgdp, unsigned long addr,
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index dea1b595f237..a80d06db4de6 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -297,7 +297,7 @@ static int alloc_init_cont_pmd(pud_t *pudp, unsigned long addr,
 {
 	int ret;
 	unsigned long next;
-	pud_t pud = READ_ONCE(*pudp);
+	pud_t pud = pudp_get(pudp);
 	pmd_t *pmdp;
 
 	/*
@@ -377,7 +377,7 @@ static int alloc_init_pud(p4d_t *p4dp, unsigned long addr, unsigned long end,
 	}
 
 	do {
-		pud_t old_pud = READ_ONCE(*pudp);
+		pud_t old_pud = pudp_get(pudp);
 
 		next = pud_addr_end(addr, end);
 
@@ -394,7 +394,7 @@ static int alloc_init_pud(p4d_t *p4dp, unsigned long addr, unsigned long end,
 			 * only allow updates to the permission attributes.
 			 */
 			BUG_ON(!pgattr_change_is_safe(pud_val(old_pud),
-						      READ_ONCE(pud_val(*pudp))));
+						      pud_val(pudp_get(pudp))));
 		} else {
 			ret = alloc_init_cont_pmd(pudp, addr, next, phys, prot,
 						  pgtable_alloc, flags);
@@ -402,7 +402,7 @@ static int alloc_init_pud(p4d_t *p4dp, unsigned long addr, unsigned long end,
 				goto out;
 
 			BUG_ON(pud_val(old_pud) != 0 &&
-			       pud_val(old_pud) != READ_ONCE(pud_val(*pudp)));
+			       pud_val(old_pud) != pud_val(pudp_get(pudp)));
 		}
 		phys += next - addr;
 	} while (pudp++, addr = next, addr != end);
@@ -1508,7 +1508,7 @@ static void unmap_hotplug_pud_range(p4d_t *p4dp, unsigned long addr,
 	do {
 		next = pud_addr_end(addr, end);
 		pudp = pud_offset(p4dp, addr);
-		pud = READ_ONCE(*pudp);
+		pud = pudp_get(pudp);
 		if (pud_none(pud))
 			continue;
 
@@ -1663,7 +1663,7 @@ static void free_empty_pud_table(p4d_t *p4dp, unsigned long addr,
 	do {
 		next = pud_addr_end(addr, end);
 		pudp = pud_offset(p4dp, addr);
-		pud = READ_ONCE(*pudp);
+		pud = pudp_get(pudp);
 		if (pud_none(pud))
 			continue;
 
@@ -1684,7 +1684,7 @@ static void free_empty_pud_table(p4d_t *p4dp, unsigned long addr,
 	 */
 	pudp = pud_offset(p4dp, 0UL);
 	for (i = 0; i < PTRS_PER_PUD; i++) {
-		if (!pud_none(READ_ONCE(pudp[i])))
+		if (!pud_none(pudp_get(pudp + i)))
 			return;
 	}
 
@@ -1796,7 +1796,7 @@ int pud_set_huge(pud_t *pudp, phys_addr_t phys, pgprot_t prot)
 	pud_t new_pud = pfn_pud(__phys_to_pfn(phys), mk_pud_sect_prot(prot));
 
 	/* Only allow permission changes for now */
-	if (!pgattr_change_is_safe(READ_ONCE(pud_val(*pudp)),
+	if (!pgattr_change_is_safe(pud_val(pudp_get(pudp)),
 				   pud_val(new_pud)))
 		return 0;
 
@@ -1827,7 +1827,7 @@ void p4d_clear_huge(p4d_t *p4dp)
 
 int pud_clear_huge(pud_t *pudp)
 {
-	if (!pud_sect(READ_ONCE(*pudp)))
+	if (!pud_sect(pudp_get(pudp)))
 		return 0;
 	pud_clear(pudp);
 	return 1;
@@ -1880,7 +1880,7 @@ int pud_free_pmd_page(pud_t *pudp, unsigned long addr)
 	pud_t pud;
 	unsigned long next, end;
 
-	pud = READ_ONCE(*pudp);
+	pud = pudp_get(pudp);
 
 	if (!pud_table(pud)) {
 		VM_WARN_ON(1);
diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
index ed1eec4c757d..581b461d4d15 100644
--- a/arch/arm64/mm/pageattr.c
+++ b/arch/arm64/mm/pageattr.c
@@ -401,7 +401,7 @@ bool kernel_page_present(struct page *page)
 		return false;
 
 	pudp = pud_offset(p4dp, addr);
-	pud = READ_ONCE(*pudp);
+	pud = pudp_get(pudp);
 	if (pud_none(pud))
 		return false;
 	if (pud_sect(pud))
diff --git a/arch/arm64/mm/trans_pgd.c b/arch/arm64/mm/trans_pgd.c
index ddde0f2983b0..71f489d439ef 100644
--- a/arch/arm64/mm/trans_pgd.c
+++ b/arch/arm64/mm/trans_pgd.c
@@ -90,7 +90,7 @@ static int copy_pmd(struct trans_pgd_info *info, pud_t *dst_pudp,
 	unsigned long next;
 	unsigned long addr = start;
 
-	if (pud_none(READ_ONCE(*dst_pudp))) {
+	if (pud_none(pudp_get(dst_pudp))) {
 		dst_pmdp = trans_alloc(info);
 		if (!dst_pmdp)
 			return -ENOMEM;
@@ -136,7 +136,7 @@ static int copy_pud(struct trans_pgd_info *info, p4d_t *dst_p4dp,
 
 	src_pudp = pud_offset(src_p4dp, start);
 	do {
-		pud_t pud = READ_ONCE(*src_pudp);
+		pud_t pud = pudp_get(src_pudp);
 
 		next = pud_addr_end(addr, end);
 		if (pud_none(pud))
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260224051153.3150613-7-anshuman.khandual%40arm.com.
