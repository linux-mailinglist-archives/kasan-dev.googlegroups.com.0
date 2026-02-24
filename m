Return-Path: <kasan-dev+bncBDGZVRMH6UCRBXXG6TGAMGQEJCG44RI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6HihFmAznWlINQQAu9opvQ
	(envelope-from <kasan-dev+bncBDGZVRMH6UCRBXXG6TGAMGQEJCG44RI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 06:13:04 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13c.google.com (mail-yx1-xb13c.google.com [IPv6:2607:f8b0:4864:20::b13c])
	by mail.lfdr.de (Postfix) with ESMTPS id D89EA181D08
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 06:13:03 +0100 (CET)
Received: by mail-yx1-xb13c.google.com with SMTP id 956f58d0204a3-64ca09f2064sf131164d50.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Feb 2026 21:13:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771909982; cv=pass;
        d=google.com; s=arc-20240605;
        b=SzRKinJDT1AdMODWG/pK4MlmsBL9nXSpDBifbyXO2tEChlk7p2Ya2wlzWUF5U1ABJ/
         PEOtStjyJNTYsfHqtfG3H95dWBCNxIa/gK4IbW/NbjE6Gnms+FKtGbPNpsugN01WLHaC
         2a6dLFKbp+jsS+lzYP0Up7cR7h4bCeXBYbS08XrRB+RGHofygK0EmFdd4K8f0i3w/323
         EPZKZAw1duTX6hIUyt5mAPbZRExwEO9CJyg1AVwmU8UT5pX27Ebq9DYoYSJwYUMycKn0
         ASLzGo/5Gz7EnQ2eMi8a5Wz80PtZckYHRGQt37d+BUy4S5EnYpH45KZdofFkcPIz6CCJ
         yAIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Mb2ov1FOnVrywZqJyKE+TlYsY9fcuHN+vswxglS1YY4=;
        fh=qrbyjctbuk5GbZrFEgGocPvCcK22qTHr1D+mLGlnAVg=;
        b=bKdr8qhuWJfXGbhchtWUMCG7u3J6/mwV1whnpeKu+5hOFBXT/N8gwsmY8ndPO0zqRo
         j+OC874XSB5LjHIZJKAH8jJIRysvy2GwtrbTJvHWe5zSH/Ia6zI4rdzYP/pwYHycbrGz
         wqe1hV0oLG9fRYzyxk+H0cxzYLkTb9NUD5FMzdswotCkvJeeVgfAZ9BDA1WveySnrBKU
         6yQXGpzNmZSZ2foTGR2E8YBScBANC0u0CQGONoJukH/Jy1BdH7de1cfJeiXnxjYv9TG7
         /yOSytU+BGMzubw2c5eLiMSUnr/oc3xfDizc3T26Ads48K4r1VCGCaNcPOGY5+J5DdTX
         YC1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771909982; x=1772514782; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Mb2ov1FOnVrywZqJyKE+TlYsY9fcuHN+vswxglS1YY4=;
        b=a2Z6asP2w/PN/PurIu5wV5lCfDPN+0u/VR2bjbmIKVNVY0qsJ0XCrTw5myVQuEl7ZF
         fiX9O5B1XmyoLWlCVKEumWiNPlcloa04ZniuH2X57fSeBYNpN9qJ17hJSe5f/Z8psMUE
         qmp7x7xNgdamp/NF6cfBu3SH8fHe2UYDUyE+FHgMqQ9enMqybZTR32+CE86a2z3eYb63
         FOltR42MG81tS4fIf+4rmxDzquFdNWJth2m2OeRRHDVjaNuseACsAZdMn6ScQOKsr/FL
         TEMBE4ddOs86TAlTl2T1yWQRKl8ZXBxWNYwl+iVzu4Ts+GVqKLBiqidSOLKAXTVySwQF
         B5gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771909982; x=1772514782;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Mb2ov1FOnVrywZqJyKE+TlYsY9fcuHN+vswxglS1YY4=;
        b=BBhLv8ltF0UAKmP1DEW8hrwYQ0FHIPiWW8FVZxiKJBl6O2+MxZ312cA+6pmEGjGlAm
         eyxREH2uxyTD99e1l6dcu+J76re8aT+XrqSgu1hS0Y1UJomKX+PrytPo+IIx8oN9zBD+
         6XLGd7Tym9fQ2pEY78U4/V4Ql0QoUzfQyQrzuUqMMqbGJVH0yLnIJxsITZ6dmRBlgaw/
         OSliFdh/OszwAbeP8vAW31R5IkOEjbHFBVmmLDV6MenYytRQI9YF+Ep04H7yvK8pNPnF
         CNR6tyRRZviJxtfxVvSNSwoIaUmHeuaEhFPJ3PiKOCexDbFH8y8a2yZTfFUWOTjaYSf3
         xsiQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWNqqFBMkpJavlJxD3OKQGb34rBtXHo523bWmmGhEGPsl8FwIZ0telSwoEvQiBTPcbYKfLvTQ==@lfdr.de
X-Gm-Message-State: AOJu0YwVEEUIrWC38TVyhJBjTTCa0vSTJmS/z2cIGReV6bByiD6mKF9v
	XvtXdy+Xwmn0EmiPouOeOAhlvQ/0o0NXh5WWziTc1Gcl0RSRo8PV4di7
X-Received: by 2002:a05:690e:16a0:b0:64a:d35e:d351 with SMTP id 956f58d0204a3-64c787d68a8mr9274344d50.25.1771909982620;
        Mon, 23 Feb 2026 21:13:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G1iqqi5ekPkR3laOc3LfwCa48CUBA1dsG+t3w6+seI0A=="
Received: by 2002:a53:d604:0:b0:648:1a47:2653 with SMTP id 956f58d0204a3-64c0e8a989dls10498361d50.1.-pod-prod-02-us;
 Mon, 23 Feb 2026 21:13:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUEYqomfhcTHQqwls9asqwiWVPERo47Ee5JGDSX+iY14nMVZw74WmZGKC+rFrNrj0/NrwIsifHYHcU=@googlegroups.com
X-Received: by 2002:a05:690e:1c08:b0:64c:99d7:8d27 with SMTP id 956f58d0204a3-64c99d7c5a1mr1852861d50.7.1771909981759;
        Mon, 23 Feb 2026 21:13:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771909981; cv=none;
        d=google.com; s=arc-20240605;
        b=HRbRU5Fn+Q5iq+fviAgoul8Th56mXSnO1m+1jdkeWyDTazImkHJmZkTFUhjBQ73aEP
         qsMSPYxfMShufuhl04bxGBWI5j89gYYfl089BgHt4/Vff5drYJUxi3l/7gBGwv4Nh4O1
         bvt+HeJxbdwV5+Lo/IJ+99YXBqj/sS68C5YIkx2HWCWHZSDW+d3RmgfLmUDtWFWx4Zcc
         1K16FlZZv9s1NpMkX2irmFoPtvnQ0AN5fVjlE9N/gJfMH4QpXlgLfkwyKD7Dn0MHCcXs
         Fk8rSv9nik+hFc6m0tfSEeUw4FBvGU4rUykrOfTPAxSKr2ScmFDJI2UvvTE+Cu1xcDka
         iNWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=FW2CMNtGRcpGXEixEdNqZypEhSH+CeHAB0KU0mw6C7M=;
        fh=/5PcxhpYFRn2Yp66x6S75u1IlAhfwysKHKXRRS1r5Qc=;
        b=klyO/fMrQBHB7ppsduTVkK98Tbd3K4wv6ovfccU5dXVUuQS5plIMHgkP7ZUGkiFrPV
         YnWyf8+EUyvk0RUOLOMoCv4N2WIwQ2nL7s13LTrmskh0Zwo9Y1zOsJagCE9BsiLZtjRn
         4Vqn/+EBpZY7W8MZV6OAo6l248K2ABYiqaxS6zcjiZhP5liIAgZRRFbcFM8HsZubrh/2
         IiEpRjvVvmw9Jx76L8gjd++3mrAXbx4MTQ22W6iwc01MlLCm9HXrUHTZ5GeL27GKXVPR
         /44zquYXmvTRgC+YAcPLsYtY+GjeLie839UGujtz/mufffQoMRHYsURyoEYzUySSAhII
         aBDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 956f58d0204a3-64c7a3a97ebsi269481d50.7.2026.02.23.21.13.01
        for <kasan-dev@googlegroups.com>;
        Mon, 23 Feb 2026 21:13:01 -0800 (PST)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id DB93D497;
	Mon, 23 Feb 2026 21:12:54 -0800 (PST)
Received: from a085714.blr.arm.com (a085714.arm.com [10.164.18.87])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id B3EC13F7BD;
	Mon, 23 Feb 2026 21:12:56 -0800 (PST)
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
Subject: [RFC V1 07/16] arm64/mm: Convert READ_ONCE() as p4dp_get() while accessing P4D
Date: Tue, 24 Feb 2026 10:41:44 +0530
Message-ID: <20260224051153.3150613-8-anshuman.khandual@arm.com>
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
	TAGGED_FROM(0.00)[bncBDGZVRMH6UCRBXXG6TGAMGQEJCG44RI];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,infradead.org:email,arm.com:mid,arm.com:email]
X-Rspamd-Queue-Id: D89EA181D08
X-Rspamd-Action: no action

Convert all READ_ONCE() based P4D accesses as p4dp_get() instead which will
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
 arch/arm64/include/asm/pgtable.h | 13 +++----------
 arch/arm64/mm/fault.c            |  2 +-
 arch/arm64/mm/fixmap.c           |  2 +-
 arch/arm64/mm/hugetlbpage.c      |  2 +-
 arch/arm64/mm/kasan_init.c       |  4 ++--
 arch/arm64/mm/mmu.c              | 29 +++++++++++++++++++++++------
 arch/arm64/mm/pageattr.c         |  2 +-
 arch/arm64/mm/trans_pgd.c        |  4 ++--
 8 files changed, 34 insertions(+), 24 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index 93d06b5de34b..24ea4e04e9a1 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -1003,12 +1003,7 @@ static inline pud_t *p4d_pgtable(p4d_t p4d)
 	return (pud_t *)__va(p4d_page_paddr(p4d));
 }
 
-static inline phys_addr_t pud_offset_phys(p4d_t *p4dp, unsigned long addr)
-{
-	BUG_ON(!pgtable_l4_enabled());
-
-	return p4d_page_paddr(READ_ONCE(*p4dp)) + pud_index(addr) * sizeof(pud_t);
-}
+phys_addr_t pud_offset_phys(p4d_t *p4dp, unsigned long addr);
 
 static inline
 pud_t *pud_offset_lockless(p4d_t *p4dp, p4d_t p4d, unsigned long addr)
@@ -1019,10 +1014,8 @@ pud_t *pud_offset_lockless(p4d_t *p4dp, p4d_t p4d, unsigned long addr)
 }
 #define pud_offset_lockless pud_offset_lockless
 
-static inline pud_t *pud_offset(p4d_t *p4dp, unsigned long addr)
-{
-	return pud_offset_lockless(p4dp, READ_ONCE(*p4dp), addr);
-}
+pud_t *pud_offset(p4d_t *p4dp, unsigned long addr);
+
 #define pud_offset	pud_offset
 
 static inline pud_t *pud_set_fixmap(unsigned long addr)
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 64836bc14798..f41f4c628d22 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -165,7 +165,7 @@ static void show_pte(unsigned long addr)
 			break;
 
 		p4dp = p4d_offset(pgdp, addr);
-		p4d = READ_ONCE(*p4dp);
+		p4d = p4dp_get(p4dp);
 		pr_cont(", p4d=%016llx", p4d_val(p4d));
 		if (p4d_none(p4d) || p4d_bad(p4d))
 			break;
diff --git a/arch/arm64/mm/fixmap.c b/arch/arm64/mm/fixmap.c
index dd58af6561e0..4c2f71929777 100644
--- a/arch/arm64/mm/fixmap.c
+++ b/arch/arm64/mm/fixmap.c
@@ -74,7 +74,7 @@ static void __init early_fixmap_init_pmd(pud_t *pudp, unsigned long addr,
 static void __init early_fixmap_init_pud(p4d_t *p4dp, unsigned long addr,
 					 unsigned long end)
 {
-	p4d_t p4d = READ_ONCE(*p4dp);
+	p4d_t p4d = p4dp_get(p4dp);
 	pud_t *pudp;
 
 	if (CONFIG_PGTABLE_LEVELS > 3 && !p4d_none(p4d) &&
diff --git a/arch/arm64/mm/hugetlbpage.c b/arch/arm64/mm/hugetlbpage.c
index b229c05bfbb6..15241307baec 100644
--- a/arch/arm64/mm/hugetlbpage.c
+++ b/arch/arm64/mm/hugetlbpage.c
@@ -288,7 +288,7 @@ pte_t *huge_pte_offset(struct mm_struct *mm,
 		return NULL;
 
 	p4dp = p4d_offset(pgdp, addr);
-	if (!p4d_present(READ_ONCE(*p4dp)))
+	if (!p4d_present(p4dp_get(p4dp)))
 		return NULL;
 
 	pudp = pud_offset(p4dp, addr);
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 19492ef5940a..e50c40162bce 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -89,7 +89,7 @@ static pmd_t *__init kasan_pmd_offset(pud_t *pudp, unsigned long addr, int node,
 static pud_t *__init kasan_pud_offset(p4d_t *p4dp, unsigned long addr, int node,
 				      bool early)
 {
-	if (p4d_none(READ_ONCE(*p4dp))) {
+	if (p4d_none(p4dp_get(p4dp))) {
 		phys_addr_t pud_phys = early ?
 				__pa_symbol(kasan_early_shadow_pud)
 					: kasan_alloc_zeroed_page(node);
@@ -162,7 +162,7 @@ static void __init kasan_p4d_populate(pgd_t *pgdp, unsigned long addr,
 	do {
 		next = p4d_addr_end(addr, end);
 		kasan_pud_populate(p4dp, addr, next, node, early);
-	} while (p4dp++, addr = next, addr != end && p4d_none(READ_ONCE(*p4dp)));
+	} while (p4dp++, addr = next, addr != end && p4d_none(p4dp_get(p4dp)));
 }
 
 static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index a80d06db4de6..16ae11b29f66 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -354,7 +354,7 @@ static int alloc_init_pud(p4d_t *p4dp, unsigned long addr, unsigned long end,
 {
 	int ret = 0;
 	unsigned long next;
-	p4d_t p4d = READ_ONCE(*p4dp);
+	p4d_t p4d = p4dp_get(p4dp);
 	pud_t *pudp;
 
 	if (p4d_none(p4d)) {
@@ -443,7 +443,7 @@ static int alloc_init_p4d(pgd_t *pgdp, unsigned long addr, unsigned long end,
 	}
 
 	do {
-		p4d_t old_p4d = READ_ONCE(*p4dp);
+		p4d_t old_p4d = p4dp_get(p4dp);
 
 		next = p4d_addr_end(addr, end);
 
@@ -453,7 +453,7 @@ static int alloc_init_p4d(pgd_t *pgdp, unsigned long addr, unsigned long end,
 			goto out;
 
 		BUG_ON(p4d_val(old_p4d) != 0 &&
-		       p4d_val(old_p4d) != READ_ONCE(p4d_val(*p4dp)));
+		       p4d_val(old_p4d) != (p4d_val(p4dp_get(p4dp))));
 
 		phys += next - addr;
 	} while (p4dp++, addr = next, addr != end);
@@ -1541,7 +1541,7 @@ static void unmap_hotplug_p4d_range(pgd_t *pgdp, unsigned long addr,
 	do {
 		next = p4d_addr_end(addr, end);
 		p4dp = p4d_offset(pgdp, addr);
-		p4d = READ_ONCE(*p4dp);
+		p4d = p4dp_get(p4dp);
 		if (p4d_none(p4d))
 			continue;
 
@@ -1703,7 +1703,7 @@ static void free_empty_p4d_table(pgd_t *pgdp, unsigned long addr,
 	do {
 		next = p4d_addr_end(addr, end);
 		p4dp = p4d_offset(pgdp, addr);
-		p4d = READ_ONCE(*p4dp);
+		p4d = p4dp_get(p4dp);
 		if (p4d_none(p4d))
 			continue;
 
@@ -1724,7 +1724,7 @@ static void free_empty_p4d_table(pgd_t *pgdp, unsigned long addr,
 	 */
 	p4dp = p4d_offset(pgdp, 0UL);
 	for (i = 0; i < PTRS_PER_P4D; i++) {
-		if (!p4d_none(READ_ONCE(p4dp[i])))
+		if (!p4d_none(p4dp_get(p4dp + i)))
 			return;
 	}
 
@@ -2258,4 +2258,21 @@ int pmdp_test_and_clear_young(struct vm_area_struct *vma,
 }
 #endif /* CONFIG_TRANSPARENT_HUGEPAGE || CONFIG_ARCH_HAS_NONLEAF_PMD_YOUNG */
 
+#if CONFIG_PGTABLE_LEVELS > 3
+phys_addr_t pud_offset_phys(p4d_t *p4dp, unsigned long addr)
+{
+	p4d_t p4d = p4dp_get(p4dp);
+
+	BUG_ON(!pgtable_l4_enabled());
+
+	return p4d_page_paddr(p4d) + pud_index(addr) * sizeof(pud_t);
+}
+
+pud_t *pud_offset(p4d_t *p4dp, unsigned long addr)
+{
+	p4d_t p4d = p4dp_get(p4dp);
+
+	return pud_offset_lockless(p4dp, p4d, addr);
+}
+#endif
 #endif
diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
index 581b461d4d15..b45190507e59 100644
--- a/arch/arm64/mm/pageattr.c
+++ b/arch/arm64/mm/pageattr.c
@@ -397,7 +397,7 @@ bool kernel_page_present(struct page *page)
 		return false;
 
 	p4dp = p4d_offset(pgdp, addr);
-	if (p4d_none(READ_ONCE(*p4dp)))
+	if (p4d_none(p4dp_get(p4dp)))
 		return false;
 
 	pudp = pud_offset(p4dp, addr);
diff --git a/arch/arm64/mm/trans_pgd.c b/arch/arm64/mm/trans_pgd.c
index 71f489d439ef..75f0a6a5a43a 100644
--- a/arch/arm64/mm/trans_pgd.c
+++ b/arch/arm64/mm/trans_pgd.c
@@ -126,7 +126,7 @@ static int copy_pud(struct trans_pgd_info *info, p4d_t *dst_p4dp,
 	unsigned long next;
 	unsigned long addr = start;
 
-	if (p4d_none(READ_ONCE(*dst_p4dp))) {
+	if (p4d_none(p4dp_get(dst_p4dp))) {
 		dst_pudp = trans_alloc(info);
 		if (!dst_pudp)
 			return -ENOMEM;
@@ -173,7 +173,7 @@ static int copy_p4d(struct trans_pgd_info *info, pgd_t *dst_pgdp,
 	src_p4dp = p4d_offset(src_pgdp, start);
 	do {
 		next = p4d_addr_end(addr, end);
-		if (p4d_none(READ_ONCE(*src_p4dp)))
+		if (p4d_none(p4dp_get(src_p4dp)))
 			continue;
 		if (copy_pud(info, dst_p4dp, src_p4dp, addr, next))
 			return -ENOMEM;
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260224051153.3150613-8-anshuman.khandual%40arm.com.
