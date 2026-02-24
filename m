Return-Path: <kasan-dev+bncBDGZVRMH6UCRBVHG6TGAMGQEPW6T52Y@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +OlIB1cznWlINQQAu9opvQ
	(envelope-from <kasan-dev+bncBDGZVRMH6UCRBVHG6TGAMGQEPW6T52Y@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 06:12:55 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb139.google.com (mail-yx1-xb139.google.com [IPv6:2607:f8b0:4864:20::b139])
	by mail.lfdr.de (Postfix) with ESMTPS id AAA2C181CF2
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 06:12:54 +0100 (CET)
Received: by mail-yx1-xb139.google.com with SMTP id 956f58d0204a3-64ad4fd4257sf8208591d50.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Feb 2026 21:12:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771909973; cv=pass;
        d=google.com; s=arc-20240605;
        b=NLVLDLx2X4+FxNCG953elrl5WETTeTeVRJubml+fGb651uRDpo3tCBzHNk1ZsUSFdP
         VTVywGDWpdX1pB1rqOi6zPYFnY/Z/w0ViKFqb5WT7fmRaiO0Fd3kEpEK8QU+lS+U3knK
         X7iu6lLLtb+Zid16iiwj39jK3P17T9NYozDwmam10bCZTrtk1PQpiL4iAiNUROXQfPu8
         Lk2rwNqHERJNBQ/lAweKJjYl8ovdHsdp7PvdcRonj+xHN7jxYEC7DBzE/THg1PTgTvhr
         zOseThRIhvhTQhMsSzKf8M5qOhTabMAVbskOZ5WTeo466ovDnBivcfOWFGgPya+HhKsP
         S5Lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=is6moiSfhGnqUZpwKa7TLU2gAlQYJaIkILc10+E7I9E=;
        fh=3CDzdhT6Zwyptix5wwFfQzs+Zkv1b1/gYH1+a68pKZg=;
        b=dNiX/g2OU9OodLUc5xrgYMVfpw2trSlHgJjeylxkBuEIlqbWn5Cxokn3QjlbLf2nel
         GQToI8c40lenHA7Q+Dne/zHX1Cj58IK7E4ugz25o4fMDWDFJn6a0JKLH2lG2JkJRBqlN
         g1dxm7SM44htIDo6FyocbnD6sQ8DexoGfMgLZQtRqAYUnukjod96TVMXgCK8xEiqbgaW
         svoMOfq4RG1tB4WdXAFriHNcIAUWnyzMxu+2FoHaoTMYwb3fAMu9XWRtWl5gnyLQFQfM
         z5S+0xk9EkWqG9Eq72kYbG1ZVoD601MS0UF3Gt5lZKEvosqxBrJvzVi0ILxiOlbdjsMp
         3wVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771909973; x=1772514773; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=is6moiSfhGnqUZpwKa7TLU2gAlQYJaIkILc10+E7I9E=;
        b=DFvO8YjkXiSfZVZaz91XOZl/rjwXpZIC9F4qabqoVW56oQhrGagZ0tXZpQ5Q5BSvSz
         vTJAe80oO7jakQe7YJpFXSi1KO2Rl0dypZO/buSgCIa/4nzvY6LWkZ2sZuoEJbnPw6vC
         8rV9T3zfw8trYid6KZwAed1QUC0UXNjEXI9c42SqodJqXUwnz1/3qImH2kU+i0rgig8m
         UiSl9R1O4dRvSMoK4VdWe6fQdY3OpcG56LTVSXd5bUpHJXxK/5BngUMZv/WzXWdoBLlG
         KQciu6xHgsj/d6L5o9gZpiRPQZcCoWgrjQrDLtO845f+NaC7yt6/Wlejxl+nlFEFUOKr
         4Eqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771909973; x=1772514773;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=is6moiSfhGnqUZpwKa7TLU2gAlQYJaIkILc10+E7I9E=;
        b=oJHNa5YPFSq1TekXtvnJQnK9/SJGQT9SO1WwgdI9yLSHn5pbBgdnIPNJgvYB4dIZ0G
         oxX9jvBsLL4E57nnlvabcFHPumum7rdeJjhYYEJgA3uJ7O0CVrDciVAAHMQzgmaeQgza
         M3ONnMpbrEJJBdQFEMytMDZmitNFVahiOaNZPgDHdZIMJeyCJGUUTVBWwP4/YCS46myu
         9wPDuryechtjmkse7qQQgZZ3JuRpu3r9PFB6Y1QF+00od1T/DDZomuW7VsmsKDxDJmbb
         KtiSvP9GrZ5qT8i2ffoOuQIBzGXYdwQbE01lAnaxLpwuAD7EX6jvNuR7fhEUdr17XAzL
         if+A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV2J3TK4Thl0iW82pLXAgGiwIdo5N6mSSkSDPhdXxwdzS/x4YtAwic1OvYP/WOFmkjJz0iahg==@lfdr.de
X-Gm-Message-State: AOJu0YyR+QAmJwkcplWXp8R/tmX1vBg/AGTKNIRa6aZ0hIEzYFiL9Mo6
	cds4DaCT54oPiNfYliyu4xCwj0yvHNrKeKpPZ+QcdLk0s97VmcCGlrAA
X-Received: by 2002:a53:c057:0:10b0:64c:5b47:db39 with SMTP id 956f58d0204a3-64c790926c3mr7877944d50.84.1771909972970;
        Mon, 23 Feb 2026 21:12:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Eo0yYYOwIKiaQtkiFmK1ZjHR0FVCAlzzhvwwReVmtMyQ=="
Received: by 2002:a53:acc8:0:10b0:646:78d8:d2c2 with SMTP id
 956f58d0204a3-64c08235148ls7714324d50.0.-pod-prod-03-us; Mon, 23 Feb 2026
 21:12:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWJWWkOTdwgIouHHVY2yd+giBgCvmUnZj7A+P/9tUBGavZ6bju5/Ddei0++lH6/0nouLhrO+V8/f30=@googlegroups.com
X-Received: by 2002:a05:690c:2605:b0:795:28b6:e3cc with SMTP id 00721157ae682-79828f34874mr102898647b3.22.1771909971753;
        Mon, 23 Feb 2026 21:12:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771909971; cv=none;
        d=google.com; s=arc-20240605;
        b=SpX6mpKfmrA6Y5+TVF9eLXaTaAKT/RGCbNSQ5MSzqyWYobK2bk2CLEw7tGy4P4E4yQ
         nmj9LuQpSYMV5z2psSZkx4rLtyqNyrcZhsPqh6AR7DCdH8p+uYIOJXIpE1PdDscmHMZv
         wdPWOyKH+GTn04iqo0li0xPspRauMrWj0TA2U3OMO6M+6VtIbLlAPsSTzXY0o6r6mNGB
         FUnc0GY4ic/94+OcX3SBxx4qWHOOjb+gIMyc5TzWk8Yw2sy9LYEhOnGDWTO5bdYv+A4f
         AEvyCDH9xsH/kJlJwGlXK48Eo0jIIVdGx2CGFkZ5ty9Mo4OZm8md8CI5PhbOfZC1PcYL
         X4gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=UmwHNPDGtWbF+MXPvm57i1l+rUY6KArEvQFmb7JFGz8=;
        fh=/5PcxhpYFRn2Yp66x6S75u1IlAhfwysKHKXRRS1r5Qc=;
        b=lquPM2RrzoeZghlOAQ8WEcuB4NEbBAtSgVjN/OmGQEQ7T5ev538hIcvIL7UuH6gaZX
         +vP2OF5rtdyG6UY8bX9yehg6eJztHWE2rFZuHmKLwsoBh6+dxZN3Wxr5uPZF4fiuXUDY
         khIzYACxVVY35unrIqGfdWAClO2iSxj2d2LqA4JNqP4Ph858yKRcCvSL/QU+ypRm9oEy
         efXKhMbl0eRgEmL2HCLrA2iqwGxQK2z+rpU4X0AEnhs7p3jMg8SDsnY6LPHkMCRMoXvc
         GKbAsNXloLSxLabkng306Q2B00eA2l0N/n0tuEhEgRepmHFa3ghlREnQAoaEJQIv0UAu
         pB2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 00721157ae682-7982ddda033si3262627b3.3.2026.02.23.21.12.51
        for <kasan-dev@googlegroups.com>;
        Mon, 23 Feb 2026 21:12:51 -0800 (PST)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B9A7B497;
	Mon, 23 Feb 2026 21:12:44 -0800 (PST)
Received: from a085714.blr.arm.com (a085714.arm.com [10.164.18.87])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 91ED33F7BD;
	Mon, 23 Feb 2026 21:12:46 -0800 (PST)
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
Subject: [RFC V1 05/16] arm64/mm: Convert READ_ONCE() as pmdp_get() while accessing PMD
Date: Tue, 24 Feb 2026 10:41:42 +0530
Message-ID: <20260224051153.3150613-6-anshuman.khandual@arm.com>
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[arm.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBDGZVRMH6UCRBVHG6TGAMGQEPW6T52Y];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[infradead.org:email,arm.com:mid,arm.com:email,googlegroups.com:email,googlegroups.com:dkim,mail-yx1-xb139.google.com:helo,mail-yx1-xb139.google.com:rdns]
X-Rspamd-Queue-Id: AAA2C181CF2
X-Rspamd-Action: no action

Convert all READ_ONCE() based PMD accesses as pmdp_get() instead which will
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
 arch/arm64/include/asm/pgtable.h | 12 +++--------
 arch/arm64/mm/fault.c            |  2 +-
 arch/arm64/mm/fixmap.c           |  2 +-
 arch/arm64/mm/hugetlbpage.c      |  2 +-
 arch/arm64/mm/kasan_init.c       |  4 ++--
 arch/arm64/mm/mmu.c              | 35 ++++++++++++++++++++++----------
 arch/arm64/mm/pageattr.c         |  2 +-
 arch/arm64/mm/trans_pgd.c        |  2 +-
 8 files changed, 34 insertions(+), 27 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index b3e58735c49b..4b5bc2c09bf2 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -852,7 +852,8 @@ static inline unsigned long pmd_page_vaddr(pmd_t pmd)
 }
 
 /* Find an entry in the third-level page table. */
-#define pte_offset_phys(dir,addr)	(pmd_page_paddr(READ_ONCE(*(dir))) + pte_index(addr) * sizeof(pte_t))
+#define pte_offset_phys(dir, addr)	(pmd_page_paddr(pmdp_get(dir)) + \
+					 pte_index(addr) * sizeof(pte_t))
 
 #define pte_set_fixmap(addr)		((pte_t *)set_fixmap_offset(FIX_PTE, addr))
 #define pte_set_fixmap_offset(pmd, addr)	pte_set_fixmap(pte_offset_phys(pmd, addr))
@@ -1328,14 +1329,7 @@ static inline int __ptep_clear_flush_young(struct vm_area_struct *vma,
 
 #if defined(CONFIG_TRANSPARENT_HUGEPAGE) || defined(CONFIG_ARCH_HAS_NONLEAF_PMD_YOUNG)
 #define __HAVE_ARCH_PMDP_TEST_AND_CLEAR_YOUNG
-static inline int pmdp_test_and_clear_young(struct vm_area_struct *vma,
-					    unsigned long address,
-					    pmd_t *pmdp)
-{
-	/* Operation applies to PMD table entry only if FEAT_HAFT is enabled */
-	VM_WARN_ON(pmd_table(READ_ONCE(*pmdp)) && !system_supports_haft());
-	return __ptep_test_and_clear_young(vma, address, (pte_t *)pmdp);
-}
+int pmdp_test_and_clear_young(struct vm_area_struct *vma, unsigned long address, pmd_t *pmdp);
 #endif /* CONFIG_TRANSPARENT_HUGEPAGE || CONFIG_ARCH_HAS_NONLEAF_PMD_YOUNG */
 
 static inline pte_t __ptep_get_and_clear_anysz(struct mm_struct *mm,
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index be9dab2c7d6a..1389ba26ec74 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -177,7 +177,7 @@ static void show_pte(unsigned long addr)
 			break;
 
 		pmdp = pmd_offset(pudp, addr);
-		pmd = READ_ONCE(*pmdp);
+		pmd = pmdp_get(pmdp);
 		pr_cont(", pmd=%016llx", pmd_val(pmd));
 		if (pmd_none(pmd) || pmd_bad(pmd))
 			break;
diff --git a/arch/arm64/mm/fixmap.c b/arch/arm64/mm/fixmap.c
index c5c5425791da..7a4bbcb39094 100644
--- a/arch/arm64/mm/fixmap.c
+++ b/arch/arm64/mm/fixmap.c
@@ -42,7 +42,7 @@ static inline pte_t *fixmap_pte(unsigned long addr)
 
 static void __init early_fixmap_init_pte(pmd_t *pmdp, unsigned long addr)
 {
-	pmd_t pmd = READ_ONCE(*pmdp);
+	pmd_t pmd = pmdp_get(pmdp);
 	pte_t *ptep;
 
 	if (pmd_none(pmd)) {
diff --git a/arch/arm64/mm/hugetlbpage.c b/arch/arm64/mm/hugetlbpage.c
index a42c05cf5640..6117aca2bac7 100644
--- a/arch/arm64/mm/hugetlbpage.c
+++ b/arch/arm64/mm/hugetlbpage.c
@@ -304,7 +304,7 @@ pte_t *huge_pte_offset(struct mm_struct *mm,
 		addr &= CONT_PMD_MASK;
 
 	pmdp = pmd_offset(pudp, addr);
-	pmd = READ_ONCE(*pmdp);
+	pmd = pmdp_get(pmdp);
 	if (!(sz == PMD_SIZE || sz == CONT_PMD_SIZE) &&
 	    pmd_none(pmd))
 		return NULL;
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index abeb81bf6ebd..709e8ad15603 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -62,7 +62,7 @@ static phys_addr_t __init kasan_alloc_raw_page(int node)
 static pte_t *__init kasan_pte_offset(pmd_t *pmdp, unsigned long addr, int node,
 				      bool early)
 {
-	if (pmd_none(READ_ONCE(*pmdp))) {
+	if (pmd_none(pmdp_get(pmdp))) {
 		phys_addr_t pte_phys = early ?
 				__pa_symbol(kasan_early_shadow_pte)
 					: kasan_alloc_zeroed_page(node);
@@ -138,7 +138,7 @@ static void __init kasan_pmd_populate(pud_t *pudp, unsigned long addr,
 	do {
 		next = pmd_addr_end(addr, end);
 		kasan_pte_populate(pmdp, addr, next, node, early);
-	} while (pmdp++, addr = next, addr != end && pmd_none(READ_ONCE(*pmdp)));
+	} while (pmdp++, addr = next, addr != end && pmd_none(pmdp_get(pmdp)));
 }
 
 static void __init kasan_pud_populate(p4d_t *p4dp, unsigned long addr,
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index a6a00accf4f9..dea1b595f237 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -201,7 +201,7 @@ static int alloc_init_cont_pte(pmd_t *pmdp, unsigned long addr,
 			       int flags)
 {
 	unsigned long next;
-	pmd_t pmd = READ_ONCE(*pmdp);
+	pmd_t pmd = pmdp_get(pmdp);
 	pte_t *ptep;
 
 	BUG_ON(pmd_sect(pmd));
@@ -257,7 +257,7 @@ static int init_pmd(pmd_t *pmdp, unsigned long addr, unsigned long end,
 	unsigned long next;
 
 	do {
-		pmd_t old_pmd = READ_ONCE(*pmdp);
+		pmd_t old_pmd = pmdp_get(pmdp);
 
 		next = pmd_addr_end(addr, end);
 
@@ -271,7 +271,7 @@ static int init_pmd(pmd_t *pmdp, unsigned long addr, unsigned long end,
 			 * only allow updates to the permission attributes.
 			 */
 			BUG_ON(!pgattr_change_is_safe(pmd_val(old_pmd),
-						      READ_ONCE(pmd_val(*pmdp))));
+						      pmd_val(pmdp_get(pmdp))));
 		} else {
 			int ret;
 
@@ -281,7 +281,7 @@ static int init_pmd(pmd_t *pmdp, unsigned long addr, unsigned long end,
 				return ret;
 
 			BUG_ON(pmd_val(old_pmd) != 0 &&
-			       pmd_val(old_pmd) != READ_ONCE(pmd_val(*pmdp)));
+			       pmd_val(old_pmd) != pmd_val(pmdp_get(pmdp)));
 		}
 		phys += next - addr;
 	} while (pmdp++, addr = next, addr != end);
@@ -1475,7 +1475,7 @@ static void unmap_hotplug_pmd_range(pud_t *pudp, unsigned long addr,
 	do {
 		next = pmd_addr_end(addr, end);
 		pmdp = pmd_offset(pudp, addr);
-		pmd = READ_ONCE(*pmdp);
+		pmd = pmdp_get(pmdp);
 		if (pmd_none(pmd))
 			continue;
 
@@ -1623,7 +1623,7 @@ static void free_empty_pmd_table(pud_t *pudp, unsigned long addr,
 	do {
 		next = pmd_addr_end(addr, end);
 		pmdp = pmd_offset(pudp, addr);
-		pmd = READ_ONCE(*pmdp);
+		pmd = pmdp_get(pmdp);
 		if (pmd_none(pmd))
 			continue;
 
@@ -1644,7 +1644,7 @@ static void free_empty_pmd_table(pud_t *pudp, unsigned long addr,
 	 */
 	pmdp = pmd_offset(pudp, 0UL);
 	for (i = 0; i < PTRS_PER_PMD; i++) {
-		if (!pmd_none(READ_ONCE(pmdp[i])))
+		if (!pmd_none(pmdp_get(pmdp + i)))
 			return;
 	}
 
@@ -1763,7 +1763,7 @@ int __meminit vmemmap_check_pmd(pmd_t *pmdp, int node,
 {
 	vmemmap_verify((pte_t *)pmdp, node, addr, next);
 
-	return pmd_sect(READ_ONCE(*pmdp));
+	return pmd_sect(pmdp_get(pmdp));
 }
 
 int __meminit vmemmap_populate(unsigned long start, unsigned long end, int node,
@@ -1810,7 +1810,7 @@ int pmd_set_huge(pmd_t *pmdp, phys_addr_t phys, pgprot_t prot)
 	pmd_t new_pmd = pfn_pmd(__phys_to_pfn(phys), mk_pmd_sect_prot(prot));
 
 	/* Only allow permission changes for now */
-	if (!pgattr_change_is_safe(READ_ONCE(pmd_val(*pmdp)),
+	if (!pgattr_change_is_safe(pmd_val(pmdp_get(pmdp)),
 				   pmd_val(new_pmd)))
 		return 0;
 
@@ -1835,7 +1835,7 @@ int pud_clear_huge(pud_t *pudp)
 
 int pmd_clear_huge(pmd_t *pmdp)
 {
-	if (!pmd_sect(READ_ONCE(*pmdp)))
+	if (!pmd_sect(pmdp_get(pmdp)))
 		return 0;
 	pmd_clear(pmdp);
 	return 1;
@@ -1847,7 +1847,7 @@ static int __pmd_free_pte_page(pmd_t *pmdp, unsigned long addr,
 	pte_t *table;
 	pmd_t pmd;
 
-	pmd = READ_ONCE(*pmdp);
+	pmd = pmdp_get(pmdp);
 
 	if (!pmd_table(pmd)) {
 		VM_WARN_ON(1);
@@ -2245,4 +2245,17 @@ int arch_set_user_pkey_access(struct task_struct *tsk, int pkey, unsigned long i
 
 	return 0;
 }
+
+#if defined(CONFIG_TRANSPARENT_HUGEPAGE) || defined(CONFIG_ARCH_HAS_NONLEAF_PMD_YOUNG)
+int pmdp_test_and_clear_young(struct vm_area_struct *vma,
+			      unsigned long address, pmd_t *pmdp)
+{
+	pmd_t pmdval = pmdp_get(pmdp);
+
+	/* Operation applies to PMD table entry only if FEAT_HAFT is enabled */
+	VM_WARN_ON(pmd_table(pmdval) && !system_supports_haft());
+	return __ptep_test_and_clear_young(vma, address, (pte_t *)pmdp);
+}
+#endif /* CONFIG_TRANSPARENT_HUGEPAGE || CONFIG_ARCH_HAS_NONLEAF_PMD_YOUNG */
+
 #endif
diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
index 358d1dc9a576..ed1eec4c757d 100644
--- a/arch/arm64/mm/pageattr.c
+++ b/arch/arm64/mm/pageattr.c
@@ -408,7 +408,7 @@ bool kernel_page_present(struct page *page)
 		return true;
 
 	pmdp = pmd_offset(pudp, addr);
-	pmd = READ_ONCE(*pmdp);
+	pmd = pmdp_get(pmdp);
 	if (pmd_none(pmd))
 		return false;
 	if (pmd_sect(pmd))
diff --git a/arch/arm64/mm/trans_pgd.c b/arch/arm64/mm/trans_pgd.c
index 18543b603c77..ddde0f2983b0 100644
--- a/arch/arm64/mm/trans_pgd.c
+++ b/arch/arm64/mm/trans_pgd.c
@@ -100,7 +100,7 @@ static int copy_pmd(struct trans_pgd_info *info, pud_t *dst_pudp,
 
 	src_pmdp = pmd_offset(src_pudp, start);
 	do {
-		pmd_t pmd = READ_ONCE(*src_pmdp);
+		pmd_t pmd = pmdp_get(src_pmdp);
 
 		next = pmd_addr_end(addr, end);
 		if (pmd_none(pmd))
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260224051153.3150613-6-anshuman.khandual%40arm.com.
