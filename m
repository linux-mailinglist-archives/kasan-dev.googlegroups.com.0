Return-Path: <kasan-dev+bncBDLKPY4HVQKBBJHAQOBAMGQEUNVXLWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id D04CC32D55C
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 15:35:16 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id d3sf9969276lfc.18
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 06:35:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614868516; cv=pass;
        d=google.com; s=arc-20160816;
        b=x13HRW0cqHdVIKdNhsBWS7CkXIYankXCSzJdgcksxeB1u5LuLj9mzLxvM0+OXhYtVV
         2icl+AnFQlTDhhUVzQHPr77wK7ZNs/qamcv77lgBHdF7VpfIhGudG/Uq6i8ViQQNJnWQ
         pjJBoldLFzICHnngS4I5Gkv82lsjr5iweVhm1jG/pcUoEZ8ztZKSZLgFlg+ltjzbuJiv
         6T4RlNnP9hNrNmurDixTNZWz6PIRIxqCqvaDkDeErE17t3cIgmAREfsCR/M4kFAjCK5l
         PU/dzQxyrPyjMk3NdZT988f8Jnmlgtep4OoV9zO5XVuxQ4l9nat6Cwpc7c/oKQ2YXxHw
         oGZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:date:cc:to:subject:from:references
         :in-reply-to:message-id:mime-version:sender:dkim-signature;
        bh=/lX/gOX/u7Y4WyCIJE8umryKKI3g/NA4nvP5Sd5Yof4=;
        b=LCIrExjXtCpN1P6e1RhjjL1TT5oXp9cKxOlHHPz51dpzoWDfjnpXx1rAOq9h9z/3MI
         m/ErRmeIel+C+tCzjeF07dFLFgN7vKD3Li8ywegGswJizBoQ2Xx6NC8pilVqPkKXMqE3
         knXXTU68WJ6eHBkXG54bWX4GgRPZ1nWJNOkCRQvPgM3GoKqs7mLOKdFd6BskKbP/J5eZ
         PeVTVs/uByvrdrrYglaWSy8D57o9SxS8B7+94osTrDepr7it/ixW5WJ6zVyiD8AxbMQZ
         ZwN0YCRXtYqkX3G6twhGAkLSNtURMIL/8iLM/Es/OnP+vq6VsR7uLAJ3l3Iw8IKGuOrQ
         gKMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:message-id:in-reply-to:references:from:subject
         :to:cc:date:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/lX/gOX/u7Y4WyCIJE8umryKKI3g/NA4nvP5Sd5Yof4=;
        b=k6kztfFy4/Ekbi8hotGBwRCd9TU6nKH8rD5/vCid5DY6g6MAOFn/3qOBCY8akuQgJ8
         5wyA89IwAiqy+XreSiRi1TCBdC1t44Vyo5Jdtt1ydF84pvIdko0bfIN7bh1lZUF6z3WG
         HMFq8u1C35s+LQVMxgSd3/9kara7gQYYSnvv4hPMp5NZEbTHZ6ORfZ6FUYjYa7zJUrxN
         tXSIcgEfPWjjpEkYNZaCHwhwEs3UtSGS8mUuqql0vQP58G4NDf8aRTc7SzueBOcFg81s
         lxpwCzvzdcZs4/YIj7hIR2m2GdBMOQbXusmUoyWlKs2qMiWZ3tlwvYvvxLZ/RV2+gyGs
         2M4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:message-id:in-reply-to
         :references:from:subject:to:cc:date:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/lX/gOX/u7Y4WyCIJE8umryKKI3g/NA4nvP5Sd5Yof4=;
        b=bqQ5mOSHg/7SpoKxOS+n7Ps/cVw2Rg5PO5V01Mg10wzwOHe3swnbKI4VOGtAxbD3bo
         2iNLo2UvLgtPd9DW3aBcwZdiVN0zC2y3iVQQ9Ak0a9fJY0Cg7ToOFvSUqRI2SF87N9sr
         8WEKzrr/uooOiOWfQIOKZpgkvS5RD92TcYUQht2oMdruAeIa+EL3k/NaP3oR0HtZao0T
         L1qxo95khsOdPHRIZclQBDLSiIMGih+47QpB/psq3O7DuThFp9fz3PFoO6z6AqqMcm5Y
         XCzBfF6FpzCyIrtrwXqIlAVyiDGjjalaMcC3Qxo/OjQBG3+gpnUNnripBcrFJfyRbEvx
         mbMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532eGmeMEAPRdCm9r4EyK1almUr2aKaXlouYbgEhPI8R+0vn0yBS
	SYxEkPUqRcCDRB4SBXgWIyM=
X-Google-Smtp-Source: ABdhPJwA2tb76g9CkrBnKHLJWJF9+8QDMf2W68ISA++05Q8Rl4v6nnfgWt3cY0uEh9cVfEMUm1qXcw==
X-Received: by 2002:a05:651c:10d1:: with SMTP id l17mr2409411ljn.205.1614868516438;
        Thu, 04 Mar 2021 06:35:16 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls1220529lfu.3.gmail; Thu,
 04 Mar 2021 06:35:15 -0800 (PST)
X-Received: by 2002:a19:c14a:: with SMTP id r71mr2438729lff.358.1614868515442;
        Thu, 04 Mar 2021 06:35:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614868515; cv=none;
        d=google.com; s=arc-20160816;
        b=wZgrByCC+GjRzFcJ9N7z7f7jguji1IOQHORAj9Ooc0b7s7Ws1qrXOkPYsV8sEeoPOA
         K72kbPsn9XBOibu2g6P8/X8gKkA1HpWENIocegChNKlkG65RTXdN2+1/WS2t0K9Cg5aW
         xI6AHMsG2PbMYw39S5BNcXReeOBIVK2mkJ3b/spvMTqazfqUJAHptnF1tUzQqHoGxWi2
         BBPllQMAW89b0DkIZtXR3IcchDi0+XZimqnWv9RtvLE4m+ISBVI7EJmzzyRIH+J2gx1M
         pz4FapeRKaQPpZIOhtOkdbQ4cduZIsHYngzCdAT4NdNF4a6oBAXGKjZUtgTJXWgnYG9m
         3i/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=date:cc:to:subject:from:references:in-reply-to:message-id;
        bh=x9JlIM0AGS0OMyrsFlZzJLJhNbkD6Tx1i+igkrqmlHQ=;
        b=aw30mq3e3x6S625ZmHL3F67wJpElu8zR/W+69kq6D8T2Webk5mYT7EXzBAPJtDBjqO
         TyVN7/mohmAfShe8oy/kdGkBMj9VEafztDM7mtkfD8fKiAP8i2nQTc4H/epvF5GxcLOf
         lXouTkoJ3jZWqRCTSEx5jTPG3GKjTx4yb/1wwZUzyKIiJlWmiyWPN16jJN+uWsuOX7UT
         wRbLoWO2njRORRBxGuuHymJVoASbxQcuZk62PGnmCJHBAqcxNPOvQJwzHj1Gkif31KyJ
         frewTzNSTyqMgtvgSX+zwNdGZECD9ofgRPHjWG8z0yab/bGIUm8Wl3mOqNG8pH7I1ZGn
         KKtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id y3si1252848lfb.6.2021.03.04.06.35.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Mar 2021 06:35:15 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Drtgh5FPfzB09ZW;
	Thu,  4 Mar 2021 15:35:12 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id UTqvgVdxCf17; Thu,  4 Mar 2021 15:35:12 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Drtgh4CJGzB09ZR;
	Thu,  4 Mar 2021 15:35:12 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 938AB8B814;
	Thu,  4 Mar 2021 15:35:14 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id PcsqHWhc5Zke; Thu,  4 Mar 2021 15:35:14 +0100 (CET)
Received: from po16121vm.idsi0.si.c-s.fr (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 4DEC18B812;
	Thu,  4 Mar 2021 15:35:13 +0100 (CET)
Received: by po16121vm.idsi0.si.c-s.fr (Postfix, from userid 0)
	id 28DBA674E6; Thu,  4 Mar 2021 14:35:13 +0000 (UTC)
Message-Id: <afaec81a551ef15345cb7d7563b3fac3d7041c3a.1614868445.git.christophe.leroy@csgroup.eu>
In-Reply-To: <8dfe1bd2abde26337c1d8c1ad0acfcc82185e0d5.1614868445.git.christophe.leroy@csgroup.eu>
References: <8dfe1bd2abde26337c1d8c1ad0acfcc82185e0d5.1614868445.git.christophe.leroy@csgroup.eu>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Subject: [PATCH v2 4/4] powerpc: Enable KFENCE on BOOK3S/64
To: Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
Date: Thu,  4 Mar 2021 14:35:13 +0000 (UTC)
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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

This reuses the DEBUG_PAGEALLOC logic.

Tested on qemu with ppc64_defconfig + CONFIG_KFENCE + CONFIG_KUNIT +
CONFIG_KFENCE_KUNIT_TEST.

Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
---
v2: New
---
 arch/powerpc/Kconfig                  |  2 +-
 arch/powerpc/include/asm/kfence.h     |  8 ++++++++
 arch/powerpc/mm/book3s64/hash_utils.c | 29 +++++++++++++++++++++------
 3 files changed, 32 insertions(+), 7 deletions(-)

diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index d46db0bfb998..67c47b60cc84 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -185,7 +185,7 @@ config PPC
 	select HAVE_ARCH_KASAN			if PPC32 && PPC_PAGE_SHIFT <= 14
 	select HAVE_ARCH_KASAN_VMALLOC		if PPC32 && PPC_PAGE_SHIFT <= 14
 	select HAVE_ARCH_KGDB
-	select HAVE_ARCH_KFENCE			if PPC32
+	select HAVE_ARCH_KFENCE			if ARCH_SUPPORTS_DEBUG_PAGEALLOC
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT
 	select HAVE_ARCH_NVRAM_OPS
diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/asm/kfence.h
index a9846b68c6b9..532cc1a92fa5 100644
--- a/arch/powerpc/include/asm/kfence.h
+++ b/arch/powerpc/include/asm/kfence.h
@@ -11,11 +11,18 @@
 #include <linux/mm.h>
 #include <asm/pgtable.h>
 
+#if defined(CONFIG_PPC64) && !defined(PPC64_ELF_ABI_v2)
+#define ARCH_FUNC_PREFIX "."
+#endif
+
 static inline bool arch_kfence_init_pool(void)
 {
 	return true;
 }
 
+#ifdef CONFIG_PPC64
+bool kfence_protect_page(unsigned long addr, bool protect);
+#else
 static inline bool kfence_protect_page(unsigned long addr, bool protect)
 {
 	pte_t *kpte = virt_to_kpte(addr);
@@ -29,5 +36,6 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 
 	return true;
 }
+#endif
 
 #endif /* __ASM_POWERPC_KFENCE_H */
diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index cb09a49be798..b967a6403e59 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -323,8 +323,8 @@ int htab_bolt_mapping(unsigned long vstart, unsigned long vend,
 			break;
 
 		cond_resched();
-		if (debug_pagealloc_enabled() &&
-			(paddr >> PAGE_SHIFT) < linear_map_hash_count)
+		if (debug_pagealloc_enabled_or_kfence() &&
+		    (paddr >> PAGE_SHIFT) < linear_map_hash_count)
 			linear_map_hash_slots[paddr >> PAGE_SHIFT] = ret | 0x80;
 	}
 	return ret < 0 ? ret : 0;
@@ -661,7 +661,7 @@ static void __init htab_init_page_sizes(void)
 	bool aligned = true;
 	init_hpte_page_sizes();
 
-	if (!debug_pagealloc_enabled()) {
+	if (!debug_pagealloc_enabled_or_kfence()) {
 		/*
 		 * Pick a size for the linear mapping. Currently, we only
 		 * support 16M, 1M and 4K which is the default
@@ -949,7 +949,7 @@ static void __init htab_initialize(void)
 
 	prot = pgprot_val(PAGE_KERNEL);
 
-	if (debug_pagealloc_enabled()) {
+	if (debug_pagealloc_enabled_or_kfence()) {
 		linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
 		linear_map_hash_slots = memblock_alloc_try_nid(
 				linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
@@ -1927,7 +1927,7 @@ long hpte_insert_repeating(unsigned long hash, unsigned long vpn,
 	return slot;
 }
 
-#ifdef CONFIG_DEBUG_PAGEALLOC
+#if defined(CONFIG_DEBUG_PAGEALLOC) || defined(CONFIG_KFENCE)
 static DEFINE_SPINLOCK(linear_map_hash_lock);
 
 static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
@@ -1982,6 +1982,21 @@ static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long lmi)
 				     mmu_kernel_ssize, 0);
 }
 
+#ifdef CONFIG_KFENCE
+bool kfence_protect_page(unsigned long addr, bool protect)
+{
+	unsigned long lmi = __pa(addr) >> PAGE_SHIFT;
+
+	if (protect)
+		kernel_unmap_linear_page(addr, lmi);
+	else
+		kernel_map_linear_page(addr, lmi);
+
+	return true;
+}
+#endif
+
+#ifdef CONFIG_DEBUG_PAGEALLOC
 void __kernel_map_pages(struct page *page, int numpages, int enable)
 {
 	unsigned long flags, vaddr, lmi;
@@ -2000,7 +2015,9 @@ void __kernel_map_pages(struct page *page, int numpages, int enable)
 	}
 	local_irq_restore(flags);
 }
-#endif /* CONFIG_DEBUG_PAGEALLOC */
+#endif
+
+#endif /* CONFIG_DEBUG_PAGEALLOC || CONFIG_KFENCE */
 
 void hash__setup_initial_memory_limit(phys_addr_t first_memblock_base,
 				phys_addr_t first_memblock_size)
-- 
2.25.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/afaec81a551ef15345cb7d7563b3fac3d7041c3a.1614868445.git.christophe.leroy%40csgroup.eu.
