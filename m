Return-Path: <kasan-dev+bncBDS6NZUJ6ILRB2NFV23QMGQEBDX3NFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CB3E97C2E6
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:56:44 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-7d4fc4652f6sf525272a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:56:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714602; cv=pass;
        d=google.com; s=arc-20240605;
        b=ewB6clQvLakh1mKFudK8EwnXHsCq466omIFubPSBih6rQ6AZr8pANSZO7Fi07lCBPe
         QP8JWvAX1ei74HWM0WPx4JAolyknviEkXCiofjIKDtcCUgrIb/1tufeUDJpQnNWhV8i5
         MH3SXrSsgsFBRUlFuz+cZ0e4seGU54+UL7o9NXWly3ksR3PPRnb3ZdW5urQkNf2fN6fP
         svL+vvC7qSNpfadHPw4XKmaiPLK4FybDfx+vwRTA5CrMGVYfpMh4JGOOQyf3wmwD+lJo
         Gbg8b+p2GtXo8MNGfE6TnS27PLFmWvN4qVD7V0b+h3zrR5I1YuQKMTa5nwXngZv3K5ro
         W89Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=0n8raV3v37GOXlZYxW0yKfkRepDfUym8kU0trylS8TM=;
        fh=iacyKmr3sd1k7h7DLqLMKPA12RMXdEnfH/PLQVrCohM=;
        b=DMox1k/wKYYWiZWe767GpLbYAW/2ZVrhGXT7egQW9g0wCCBfmiUpXHUDy3G+c0qAjI
         JJ2rL2OYXhKl2oFnn4ULN9QWxlsTAXmGmvWTNY3xxflwk2gzmrpNxep1YG0FhYHTgULH
         bMpbPE0mG/oDv9zAmHbVfQ/IzpVgh/5U1mcRBQXILs4XUD3clxG4uGOKioMR2buumAje
         pDTH/1V7h1H3x9vIKqPdbQK75B1qYlGT9Xt1Uf/SX7GqQg1J0WI76sbYTGB76ummJtes
         ZOq2lg2CB2hP4+Wp+J+jtqaLEnKLQK3VZEeeUYns6PLaPRS76UkQ8i2cgE3BsTzXBrr6
         ka7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XEtpIX7n;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714602; x=1727319402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0n8raV3v37GOXlZYxW0yKfkRepDfUym8kU0trylS8TM=;
        b=W5TJRYGR6G112yeyril8VwpJvzp9xPwyvL3FRMi5nknal5mWcUul4s1vASM+ncGXH/
         dUKY9bCVGTqaQAyYTFk3WPPznfwEf7gVGoeLUR/4CjGafqLheT3p3GEeYOlW285KPV8v
         GPrwkL2seKw4PtO42eFlSIEFjg44lc967epjuB4z/ue0g57vtFHbHNMLZwRx01JbjVXv
         woA9NqxT0o2FbvbPmTczHsbmETomalu/tkixjYsE8WGmI6Rp+xoDwyf6enKAamyFQ2yN
         kttfk0x6Niaes+BtVwSBdzkHDMTxNqdjhslq80bOi1OM3XgOxyDkaZQzczCQh3RnFVHP
         zsGw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714602; x=1727319402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=0n8raV3v37GOXlZYxW0yKfkRepDfUym8kU0trylS8TM=;
        b=C6iV2H2rCuZAWbcUxMsoVm4P8rCCFvsB0KmkSrlQ19A8asttvivB+WPdT28IOWF0Wf
         rjRTlsNbQzdB1E5gnDVh48iPNjslepjjkO1HyjaGhPFuv8HSLBfha0h8oku+YLQJgtxd
         c/8Y1acbwC/CZLM/9jhrRde413sEwqMl0tQ75aePDNI9msjZFNHn42tPHC8SklzO68+a
         kPnmJKogOl4YX/ocYDRIYDkZAOzcp+NzDCmtn/UVvhdfiWkSvdmmZgQ9AnGNuO6cwC6m
         Fp1KSwjUs61asV5PSC5owXz7mJYLAuu+ImKDK2HQV8swMAd/ViDjn0ObEq56XwhkCjO5
         Bblw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714602; x=1727319402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0n8raV3v37GOXlZYxW0yKfkRepDfUym8kU0trylS8TM=;
        b=oLo3UiBc6j/215Ue6mkYT5tVdl+TIvTE0ArcNT6/VPgACkRs4vK29vwA6flL5zy8IW
         eezBPP+xxEK5cN2btEzCVyhBNsnDsyFpt6+YwNKjgOIRIbJ6wX7Dnb+/O4loAT0PG2U+
         6uRFMFBBCEPAXPm2L3LjXNYlDw6DmYpf073QqAUWjq/XVBcf9ukPv8wVAPtyIWB9aUTZ
         CNM+Z79XISY3FNz2UoZBKfb+7i4iEUBPvB5t/q1qfogNWMriW0FVbovODMqZXGASH0m6
         S5zTqgijlkciO3H+43GmS+vpKS/crkGN3RFsWfKsXh9cEd5HiXPZ4/a+JXfhmaK7jaWN
         xWMA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWFhcttStFNSIQ7yraYEYDDR885wLmUCz2Bd0n9bGAaLTpPe1UiU02gryBCh8aWBuaCHxGQdA==@lfdr.de
X-Gm-Message-State: AOJu0YzXafK+MA3j6DUyHTDZ4wOxLYDGeU8IXOMTNrruk+04+P2ZvedM
	FFX3hbJOKJbz3m9NP5fAnWqVFEUzvLjo5nqM8dQYXudPC8eWobtL
X-Google-Smtp-Source: AGHT+IED+YxgILTG4a3/7N1Uc6ThNgJS8Wa3dNLLEAB/Sy9pYuo7YWPJv1fVYCojkV4FFuqRh/ttDA==
X-Received: by 2002:a05:6a21:1813:b0:1cf:37f8:7a1f with SMTP id adf61e73a8af0-1cf75ea233bmr39621353637.6.1726714602070;
        Wed, 18 Sep 2024 19:56:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:a8c:b0:70a:fd97:f05b with SMTP id
 d2e1a72fcca58-7198e5a5809ls556030b3a.1.-pod-prod-03-us; Wed, 18 Sep 2024
 19:56:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXqP1t6Ei2tc0sfMH9u8sf+siudsBT5MOZk5iZoIqHYi4Mq3Vbi6nJCoqCpdHnK7x1mH+X/2wM/404=@googlegroups.com
X-Received: by 2002:a05:6a00:1ad2:b0:717:8f4b:afd6 with SMTP id d2e1a72fcca58-719261e777dmr35721158b3a.20.1726714600692;
        Wed, 18 Sep 2024 19:56:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714600; cv=none;
        d=google.com; s=arc-20240605;
        b=lV5Wl3avwqxcx07QZqLmjcBtkR0CmwH3skrUxXPhGcp/DdiWxaLsKuWng2EhMamkJR
         MZNQXk1kISOITq3sJvbasB3PLVJktLQervuL2G9GQkFXmR7LLz3w9iEQwnpClENN+KJ1
         UdCTsE1S0DvjtQXA5qleOEX4XffDRXR3WP5MTaDArOi2Fqh6EtDZg/02nr+95pGYKM2c
         Bzg2r1+nv8DMw2mYt9CZxdoswPt0NjKuZ4FfKSuNs0ErpGmXuxlrlT0VW7LTSxV4qAyR
         /upTKMQgVf8OTbTJwtC4tWXUsmHGbHGgJQpk7Du84YtaW377IM9/mG4HdXV0Uzs6ixqK
         ik/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9gdBU6NTSnQ45ASWgUOhpCdQmMAIjthCFPvKHCG5k1I=;
        fh=Jnn3hqutPUOGdFTqncXZJq7Ikx7k/rFkFpjV4ghdOh0=;
        b=F7yLTWPHFn7KRhXmp/KDNIwfL6mluqMnYLEL1sPIgJdH9mwRBs9lERJHoKWu7SqfUP
         qawl7XnHW8VFH/6pkVEAQJ3AM7dLvEO2wX3Wt2HoiH83LeI40tLMzc36dF1g16H4Qp8l
         VYUxIFypvxyACiaP8uP1z2lvlIH6nepuYoa/zP2dJb6C8Qq3C55N/HmjXA0KcX49/myL
         PidCwAooeHaArfncjI8Ur2Ib5QEMtb/i39zXwpM+YZOk5nrL4FenVDnlZ4mBsgu61EKr
         fwR7Sd+04ka0Iq9LagJNowMe0CSoa/xK6N9v2XCeEZnJZCqgz0p/9bYhklOBygGRnFu+
         zsrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XEtpIX7n;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71944ab9b89si494262b3a.2.2024.09.18.19.56.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:56:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-2053616fa36so5557665ad.0
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:56:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWRfqaokXomLlxretF/xVprsvwl0hUo636+k9PCSAOlUlfUx+atXP3TMU9l6ZUATJbvTPZmqxpQEms=@googlegroups.com
X-Received: by 2002:a17:902:e812:b0:206:c75a:29d9 with SMTP id d9443c01a7336-2076e3eb0cbmr391823725ad.42.1726714600089;
        Wed, 18 Sep 2024 19:56:40 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.56.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:56:39 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	Nirjhar Roy <nirjhar@linux.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC v2 03/13] book3s64/hash: Remove kfence support temporarily
Date: Thu, 19 Sep 2024 08:26:01 +0530
Message-ID: <5f6809f3881d5929eedc33deac4847bf41a063b9.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1726571179.git.ritesh.list@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XEtpIX7n;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62e
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Kfence on book3s Hash on pseries is anyways broken. It fails to boot
due to RMA size limitation. That is because, kfence with Hash uses
debug_pagealloc infrastructure. debug_pagealloc allocates linear map
for entire dram size instead of just kfence relevant objects.
This means for 16TB of DRAM it will require (16TB >> PAGE_SHIFT)
which is 256MB which is half of RMA region on P8.
crash kernel reserves 256MB and we also need 2048 * 16KB * 3 for
emergency stack and some more for paca allocations.
That means there is not enough memory for reserving the full linear map
in the RMA region, if the DRAM size is too big (>=16TB)
(The issue is seen above 8TB with crash kernel 256 MB reservation).

Now Kfence does not require linear memory map for entire DRAM.
It only needs for kfence objects. So this patch temporarily removes the
kfence functionality since debug_pagealloc code needs some refactoring.
We will bring in kfence on Hash support in later patches.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/include/asm/kfence.h     |  5 +++++
 arch/powerpc/mm/book3s64/hash_utils.c | 16 +++++++++++-----
 2 files changed, 16 insertions(+), 5 deletions(-)

diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/asm/kfence.h
index fab124ada1c7..f3a9476a71b3 100644
--- a/arch/powerpc/include/asm/kfence.h
+++ b/arch/powerpc/include/asm/kfence.h
@@ -10,6 +10,7 @@
 
 #include <linux/mm.h>
 #include <asm/pgtable.h>
+#include <asm/mmu.h>
 
 #ifdef CONFIG_PPC64_ELF_ABI_V1
 #define ARCH_FUNC_PREFIX "."
@@ -25,6 +26,10 @@ static inline void disable_kfence(void)
 
 static inline bool arch_kfence_init_pool(void)
 {
+#ifdef CONFIG_PPC64
+	if (!radix_enabled())
+		return false;
+#endif
 	return !kfence_disabled;
 }
 #endif
diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index e1eadd03f133..296bb74dbf40 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -431,7 +431,7 @@ int htab_bolt_mapping(unsigned long vstart, unsigned long vend,
 			break;
 
 		cond_resched();
-		if (debug_pagealloc_enabled_or_kfence() &&
+		if (debug_pagealloc_enabled() &&
 			(paddr >> PAGE_SHIFT) < linear_map_hash_count)
 			linear_map_hash_slots[paddr >> PAGE_SHIFT] = ret | 0x80;
 	}
@@ -814,7 +814,7 @@ static void __init htab_init_page_sizes(void)
 	bool aligned = true;
 	init_hpte_page_sizes();
 
-	if (!debug_pagealloc_enabled_or_kfence()) {
+	if (!debug_pagealloc_enabled()) {
 		/*
 		 * Pick a size for the linear mapping. Currently, we only
 		 * support 16M, 1M and 4K which is the default
@@ -1134,7 +1134,7 @@ static void __init htab_initialize(void)
 
 	prot = pgprot_val(PAGE_KERNEL);
 
-	if (debug_pagealloc_enabled_or_kfence()) {
+	if (debug_pagealloc_enabled()) {
 		linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
 		linear_map_hash_slots = memblock_alloc_try_nid(
 				linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
@@ -2120,7 +2120,7 @@ void hpt_do_stress(unsigned long ea, unsigned long hpte_group)
 	}
 }
 
-#if defined(CONFIG_DEBUG_PAGEALLOC) || defined(CONFIG_KFENCE)
+#ifdef CONFIG_DEBUG_PAGEALLOC
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
 
 static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
@@ -2194,7 +2194,13 @@ int hash__kernel_map_pages(struct page *page, int numpages, int enable)
 	local_irq_restore(flags);
 	return 0;
 }
-#endif /* CONFIG_DEBUG_PAGEALLOC || CONFIG_KFENCE */
+#else /* CONFIG_DEBUG_PAGEALLOC */
+int hash__kernel_map_pages(struct page *page, int numpages,
+					 int enable)
+{
+	return 0;
+}
+#endif /* CONFIG_DEBUG_PAGEALLOC */
 
 void hash__setup_initial_memory_limit(phys_addr_t first_memblock_base,
 				phys_addr_t first_memblock_size)
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5f6809f3881d5929eedc33deac4847bf41a063b9.1726571179.git.ritesh.list%40gmail.com.
