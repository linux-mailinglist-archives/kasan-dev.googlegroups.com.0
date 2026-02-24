Return-Path: <kasan-dev+bncBDGZVRMH6UCRBY7G6TGAMGQE37C36UQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6PdgBWYznWlINQQAu9opvQ
	(envelope-from <kasan-dev+bncBDGZVRMH6UCRBY7G6TGAMGQE37C36UQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 06:13:10 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 80451181D0F
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 06:13:09 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-45f07dad7a8sf17256983b6e.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Feb 2026 21:13:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771909988; cv=pass;
        d=google.com; s=arc-20240605;
        b=Evhf3Oyd2j9i5Z13tetypKQI9zJWKUZol8Y/WUZwIx9HkXiuRaBX4bkvWCSkTUI7t3
         mBF6PsrvMmfFwhl4eFO3Ps1YQiQKj5vL4HdCixN+sNIHVhFnRHWGhEkiQ1rJ+FmFmYGk
         qTUq6yv3OvluRs0R2sraRAvN/Q1mzTb/YtBR8NTIXBqDS3APExF1N0587cLlbdDtZ3m/
         EFHa4BmqKkconpYklTLVz5R1dEdh/WM84qRjIq2zoyswRyuct/Gqq+GM6uqfhO4cog67
         XOwo+NWyxFEUwwR8PV8B/orSSVkc0H9EzR5kipvp0zGeqDA22g0Gx5dmawfTSnbLEdMK
         a7kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SQTh5ibbsOLJQ3MwUUqc9dJTsX3tk53NEr1wbYYxZIA=;
        fh=t4RLjYtI3Goznp4ehovTyOrJFJYSnrahpBBVm+WIGrg=;
        b=jWeE4XNAyxyu3S2it6MgTd4mK7l6cMReDpKvFdVLNQl3w60M90ItKfxf6VVAiELwJA
         laCjndJXeOFM6k70G9p0Da//GueWd8KF3IAxNnfPFcDtWhY07T4ATx94pyZKrQQaFYbX
         ZdFlhrHUlWwWBvstZSQJBAhnY8F2kB0hqpBiFTEobRy7/zG/bPB/IboKnUpTggbOUmt3
         yJ4ktOu0vo3OcJNGgX2bZ67A0dh/2Ibmezry5x8d0vKQafB5tSujaKYNVDmN0k1WscvZ
         zlTCrJJLYsMVNTJqdN70mffahdaTc/O9F5gzvQxzXxUHkx+gkpNVjlpYmR6qFbdtXei8
         436A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771909988; x=1772514788; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SQTh5ibbsOLJQ3MwUUqc9dJTsX3tk53NEr1wbYYxZIA=;
        b=Wx+DkNtBfy006gCUGvZrBXPIgLd1xcrb7WnjrfeXmzvDn8aLHZGx5JJd1IA9vabA6t
         1eSwy9T+EkTcMZjuBAdx+2u821a3ZS3uJLyXcUegXjVNXHfAhw8al0qwZxWCcEetndsk
         xWk/TeizLOaTuy32jqTw0ViZTrGCjd20V6q5h6bXxYlsc6VzGe95u0bLPeoOxiOJrdzv
         h6Dfw9JGjSm+eYYu70dRYe7us41LtcjhBc+sH/phJmt9rJ491pwaeX5MGp5EUS16Z+Ou
         N5s46Tt/jDtCncG2OR7j8HAnbZQ3OUNFPOtN23gX8pCSfkJIOr6Qn9YE/MKQvFxZgNTp
         mz+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771909988; x=1772514788;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SQTh5ibbsOLJQ3MwUUqc9dJTsX3tk53NEr1wbYYxZIA=;
        b=CSdiElqalDXm5l9hxxJPVMHOUdj8Wlcv7XmSb7WjEcFrkRTcfv7snrqgvp4mlwwzJN
         DsboNs6ANlA4YRSUCuuY1y3fbGbeu/Kn8eDFuYFzGAS3Qzpwmh3zasA/FePkI5WsMNSe
         0RglIhd5Z4KHxlvvXy+NW3xYbw9s650uuBaFWcpYrtpMc38zClNkqOXZRBHzD3HwI1D/
         VSojveomySiPjE1eKI0rJRbP26bGBCuwMbbyYjf2vKn89P4s257ElEdK81nLppMPTCX7
         C326/FAurqCKMlYYLEHiCwyoaNvFPJiockkjmCm+c9icY0ZsWmk5X4OnekPAYfRw8zOn
         XdDg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWBawy8hYVEh7TzNnibB5X2XvKcydzJplManxwTcZS4Dso8oQubuGdUasH3hrEsH960m4XKbA==@lfdr.de
X-Gm-Message-State: AOJu0YyVCAiu7iUE0lzLZnK92eBbSpyLT0ardnxKpX4HB7gFGHPfV5Uz
	6EkEFz1qttpJeFJdYZf/LJis/C+TYtakrOxezZAeu7a66MaJ1l0zgJhU
X-Received: by 2002:a05:6870:648a:b0:40e:b6b2:b97a with SMTP id 586e51a60fabf-4157b190f40mr4879353fac.51.1771909987569;
        Mon, 23 Feb 2026 21:13:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HmDTe7yFLU9OqvF0iU6W/fKZ1Vfi0yZ6V6uBONg6LsHQ=="
Received: by 2002:a05:6870:d153:b0:40e:e4dd:d0b0 with SMTP id
 586e51a60fabf-40ee4ddd79fls6510798fac.1.-pod-prod-06-us; Mon, 23 Feb 2026
 21:13:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW3ampbQ5NJig/sthUrMKfb8NqzI4VvY+V21lUUZu/Mnk065Aqte8A2dLylaCEUzZfMtxrsLgcBeeM=@googlegroups.com
X-Received: by 2002:a05:6871:783:b0:409:6ea8:5f7f with SMTP id 586e51a60fabf-4157ac6b0d7mr5538009fac.20.1771909986578;
        Mon, 23 Feb 2026 21:13:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771909986; cv=none;
        d=google.com; s=arc-20240605;
        b=QRccZYosd869cNv+Xj1H/i2mUz76e8fz/SQlCaKQWWpkFViQdfjsMEMgoNfuXAiinz
         RCr/zQRQktDTByexhqexdrxRCAxQZXEzupikEAsKl+b3EmI2XFNpSfXKyw9oUKZUMK47
         zURQimui72O4Z29j5NjwaRU1SdK3UGPRGwDlkIzFRQ4mRHzxisQOQP2cGO6k5sst0BKb
         uGjxAf712AxmCZxleD5d1qTEjznumhNAHvg8ZryLTqxp9KapkqwmcPlHkSmp8q7YVVqS
         5BoPKYjMOjuRfGw9/oSeQHcOX0Ay/ui35QTO7z85WYE+BxUFFNyXlS2TDZCvyx8skhRL
         lkUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=RxiVFUuLeDkSxqT3ivdHS3XEaH5+5qZe/ROqDJWk8+A=;
        fh=/5PcxhpYFRn2Yp66x6S75u1IlAhfwysKHKXRRS1r5Qc=;
        b=Kg4bbH4BzQ13dNXNbtaBrpGA2y5rRcvQ2zFh2NcRwHMzVnLnoN07HeSMTTR2dluQ1+
         p0ce/yjh4gDcaw+sMmOrJPIgNVAVVPbVlFzHUfzNFCd9VZCRvcc2X/fR9jX9sbN6QTdD
         9wArtc3ek7Ky+4CVmN+96aRlgPEbpFLXCSvaqLimCwIY0VjhZ2XvJZEotpNYvUBAH55t
         9R7PCrdYXSmkkOtTlmi4sgKihJQ+yUFQdrsgDtka8naWUuwy8lLBxRaK77AreSwAwLBe
         Aqfhpv29IeniJbvDeUhqrOJGt8dHNjk4nxsglGU3ovplRoDGro/XGt8CKPcZj/lWRcjz
         B/xA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 586e51a60fabf-4157cd3e99fsi279798fac.2.2026.02.23.21.13.06
        for <kasan-dev@googlegroups.com>;
        Mon, 23 Feb 2026 21:13:06 -0800 (PST)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EDB95497;
	Mon, 23 Feb 2026 21:12:59 -0800 (PST)
Received: from a085714.blr.arm.com (a085714.arm.com [10.164.18.87])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id C46A93F7BD;
	Mon, 23 Feb 2026 21:13:01 -0800 (PST)
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
Subject: [RFC V1 08/16] arm64/mm: Convert READ_ONCE() as pgdp_get() while accessing PGD
Date: Tue, 24 Feb 2026 10:41:45 +0530
Message-ID: <20260224051153.3150613-9-anshuman.khandual@arm.com>
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
	TAGGED_FROM(0.00)[bncBDGZVRMH6UCRBY7G6TGAMGQE37C36UQ];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[infradead.org:email,arm.com:mid,arm.com:email,googlegroups.com:email,googlegroups.com:dkim,mail-oi1-x238.google.com:helo,mail-oi1-x238.google.com:rdns]
X-Rspamd-Queue-Id: 80451181D0F
X-Rspamd-Action: no action

Convert all READ_ONCE() based PGD accesses as pgdp_get() instead which will
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
 arch/arm64/include/asm/pgtable.h | 12 ++----------
 arch/arm64/mm/fault.c            |  2 +-
 arch/arm64/mm/hugetlbpage.c      |  2 +-
 arch/arm64/mm/kasan_init.c       |  2 +-
 arch/arm64/mm/mmu.c              | 25 ++++++++++++++++++++++---
 arch/arm64/mm/pageattr.c         |  2 +-
 arch/arm64/mm/trans_pgd.c        |  4 ++--
 7 files changed, 30 insertions(+), 19 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index 24ea4e04e9a1..257af1c3015d 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -1119,12 +1119,7 @@ static inline p4d_t *pgd_to_folded_p4d(pgd_t *pgdp, unsigned long addr)
 	return (p4d_t *)PTR_ALIGN_DOWN(pgdp, PAGE_SIZE) + p4d_index(addr);
 }
 
-static inline phys_addr_t p4d_offset_phys(pgd_t *pgdp, unsigned long addr)
-{
-	BUG_ON(!pgtable_l5_enabled());
-
-	return pgd_page_paddr(READ_ONCE(*pgdp)) + p4d_index(addr) * sizeof(p4d_t);
-}
+phys_addr_t p4d_offset_phys(pgd_t *pgdp, unsigned long addr);
 
 static inline
 p4d_t *p4d_offset_lockless(pgd_t *pgdp, pgd_t pgd, unsigned long addr)
@@ -1135,10 +1130,7 @@ p4d_t *p4d_offset_lockless(pgd_t *pgdp, pgd_t pgd, unsigned long addr)
 }
 #define p4d_offset_lockless p4d_offset_lockless
 
-static inline p4d_t *p4d_offset(pgd_t *pgdp, unsigned long addr)
-{
-	return p4d_offset_lockless(pgdp, READ_ONCE(*pgdp), addr);
-}
+p4d_t *p4d_offset(pgd_t *pgdp, unsigned long addr);
 
 static inline p4d_t *p4d_set_fixmap(unsigned long addr)
 {
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index f41f4c628d22..7bb14765a98d 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -152,7 +152,7 @@ static void show_pte(unsigned long addr)
 		 mm == &init_mm ? "swapper" : "user", PAGE_SIZE / SZ_1K,
 		 vabits_actual, mm_to_pgd_phys(mm));
 	pgdp = pgd_offset(mm, addr);
-	pgd = READ_ONCE(*pgdp);
+	pgd = pgdp_get(pgdp);
 	pr_alert("[%016lx] pgd=%016llx", addr, pgd_val(pgd));
 
 	do {
diff --git a/arch/arm64/mm/hugetlbpage.c b/arch/arm64/mm/hugetlbpage.c
index 15241307baec..ccf08ba06a48 100644
--- a/arch/arm64/mm/hugetlbpage.c
+++ b/arch/arm64/mm/hugetlbpage.c
@@ -284,7 +284,7 @@ pte_t *huge_pte_offset(struct mm_struct *mm,
 	pmd_t *pmdp, pmd;
 
 	pgdp = pgd_offset(mm, addr);
-	if (!pgd_present(READ_ONCE(*pgdp)))
+	if (!pgd_present(pgdp_get(pgdp)))
 		return NULL;
 
 	p4dp = p4d_offset(pgdp, addr);
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index e50c40162bce..d05c16cfa5aa 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -102,7 +102,7 @@ static pud_t *__init kasan_pud_offset(p4d_t *p4dp, unsigned long addr, int node,
 static p4d_t *__init kasan_p4d_offset(pgd_t *pgdp, unsigned long addr, int node,
 				      bool early)
 {
-	if (pgd_none(READ_ONCE(*pgdp))) {
+	if (pgd_none(pgdp_get(pgdp))) {
 		phys_addr_t p4d_phys = early ?
 				__pa_symbol(kasan_early_shadow_p4d)
 					: kasan_alloc_zeroed_page(node);
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 16ae11b29f66..bcf32d1a92de 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -420,7 +420,7 @@ static int alloc_init_p4d(pgd_t *pgdp, unsigned long addr, unsigned long end,
 {
 	int ret;
 	unsigned long next;
-	pgd_t pgd = READ_ONCE(*pgdp);
+	pgd_t pgd = pgdp_get(pgdp);
 	p4d_t *p4dp;
 
 	if (pgd_none(pgd)) {
@@ -1567,7 +1567,7 @@ static void unmap_hotplug_range(unsigned long addr, unsigned long end,
 	do {
 		next = pgd_addr_end(addr, end);
 		pgdp = pgd_offset_k(addr);
-		pgd = READ_ONCE(*pgdp);
+		pgd = pgdp_get(pgdp);
 		if (pgd_none(pgd))
 			continue;
 
@@ -1742,7 +1742,7 @@ static void free_empty_tables(unsigned long addr, unsigned long end,
 	do {
 		next = pgd_addr_end(addr, end);
 		pgdp = pgd_offset_k(addr);
-		pgd = READ_ONCE(*pgdp);
+		pgd = pgdp_get(pgdp);
 		if (pgd_none(pgd))
 			continue;
 
@@ -2275,4 +2275,23 @@ pud_t *pud_offset(p4d_t *p4dp, unsigned long addr)
 	return pud_offset_lockless(p4dp, p4d, addr);
 }
 #endif
+
+#if CONFIG_PGTABLE_LEVELS > 4
+phys_addr_t p4d_offset_phys(pgd_t *pgdp, unsigned long addr)
+{
+	pgd_t pgd = pgdp_get(pgdp);
+
+	BUG_ON(!pgtable_l5_enabled());
+
+	return pgd_page_paddr(pgd) + p4d_index(addr) * sizeof(p4d_t);
+}
+
+p4d_t *p4d_offset(pgd_t *pgdp, unsigned long addr)
+{
+	pgd_t pgd = pgdp_get(pgdp);
+
+	return p4d_offset_lockless(pgdp, pgd, addr);
+}
+#endif
+
 #endif
diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
index b45190507e59..0928946a9b19 100644
--- a/arch/arm64/mm/pageattr.c
+++ b/arch/arm64/mm/pageattr.c
@@ -393,7 +393,7 @@ bool kernel_page_present(struct page *page)
 	unsigned long addr = (unsigned long)page_address(page);
 
 	pgdp = pgd_offset_k(addr);
-	if (pgd_none(READ_ONCE(*pgdp)))
+	if (pgd_none(pgdp_get(pgdp)))
 		return false;
 
 	p4dp = p4d_offset(pgdp, addr);
diff --git a/arch/arm64/mm/trans_pgd.c b/arch/arm64/mm/trans_pgd.c
index 75f0a6a5a43a..a3a48c88e05c 100644
--- a/arch/arm64/mm/trans_pgd.c
+++ b/arch/arm64/mm/trans_pgd.c
@@ -162,7 +162,7 @@ static int copy_p4d(struct trans_pgd_info *info, pgd_t *dst_pgdp,
 	unsigned long next;
 	unsigned long addr = start;
 
-	if (pgd_none(READ_ONCE(*dst_pgdp))) {
+	if (pgd_none(pgdp_get(dst_pgdp))) {
 		dst_p4dp = trans_alloc(info);
 		if (!dst_p4dp)
 			return -ENOMEM;
@@ -192,7 +192,7 @@ static int copy_page_tables(struct trans_pgd_info *info, pgd_t *dst_pgdp,
 	dst_pgdp = pgd_offset_pgd(dst_pgdp, start);
 	do {
 		next = pgd_addr_end(addr, end);
-		if (pgd_none(READ_ONCE(*src_pgdp)))
+		if (pgd_none(pgdp_get(src_pgdp)))
 			continue;
 		if (copy_p4d(info, dst_pgdp, src_pgdp, addr, next))
 			return -ENOMEM;
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260224051153.3150613-9-anshuman.khandual%40arm.com.
