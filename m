Return-Path: <kasan-dev+bncBCSMHHGWUEMBBC4RSWGAMGQETNAX66I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 54C45446571
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Nov 2021 16:06:53 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id r8-20020a056830448800b00552d0eff1b2sf5002879otv.7
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Nov 2021 08:06:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1636124812; cv=pass;
        d=google.com; s=arc-20160816;
        b=SjUSpwO0OaQIaDYj96/81Hfhh23TaFmITen/r4ZgzpI3zgRQ8wBNXDRjWCKzOvaYfd
         Sh8SPB5XMniDh9hW5PZUELAaSU/bIJaIlE+ky6Uu6Lbuijf/zfZ1Ax8jdnFgb2dD7m1J
         DX4K/U7OOlkmMSDZ09RuYtHchZS/p6MsjM2+tkjjzTvDvMo7Dn6tqbj3Sz0R+nBiwgt9
         EvI1uuGWnzs8bobGl7KblrI+5nJ23ZN7cOgjzUidRFMuwH8MVktLx+UEOQFot2aObzh9
         x2dkF/FAXX5Jd2kv2rsnEYzz/ANSBBT3sL1iGU643TI29Xk3DzUZW/cQ67EXa38DrnDq
         vmmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=BWkAbvsbL7OhQ2TXr4MJpC6VxahgjACMW1npI0RBuIM=;
        b=pOGT/w3H2cQfbXYHQH2eWb32yIVMWfQp4NLwcdLRzX0FBJOqS/J3ep3El+NIl7P19Q
         bV4sssSOHMs7TUXjuhucp6Hm+ugA85kHsqVlDd1/gxpgP3jUhR8qmVEgdsrsgEHYuoP4
         Mb4v0I/cLR4Z7Of0yIzCFSnkmvVes6TR8BkM2AZeDTKev+2DnhAOlu41+JwotZkVUJey
         ++oFy6HSSvNoGy9pawEUKsnL+OJrUY2j01aRNGXTvE5IVCo9q3Wo+jl28ae4vMhBLwgJ
         rvTlnIqLHkSxnxjPaPrTn9OQ2hGooJrSt7q3Qxv671NlfMy+4/Hi4qcqIuxQsJyCCG8/
         i5FA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=w5k1KDtd;
       spf=pass (google.com: domain of quic_qiancai@quicinc.com designates 129.46.98.28 as permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BWkAbvsbL7OhQ2TXr4MJpC6VxahgjACMW1npI0RBuIM=;
        b=bIdNckNwV49Qg9jwXxFBdp8mkFc600JMyQhYEq/okNf+z1TfVXIH/rUDGiCgnNCF3F
         TPWPVfdsOx1W0Mwz9657xt2fj6FhWkAosjpA+8jgc4pIoPUjdghxFhhOI1SlqO5Q+Qjz
         eH41bVLpkri00eNMOpeDODZghvNVWJzCmobydLGbpYrY5gwPf7d+SLebZNpalz/8c+3R
         0yVlOHiJqJJqCW1m0nQjpEHGnMBq1y9iAuWohaLyZSJPEl8HNre3u+M0L9gjp0lllGjw
         GldrVvlAXcl2deJWhgHkW8dAqbQmyYfv/90MSzzzNrGZnbQ9d0wXByVgS1QN55FLAqg9
         EcUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BWkAbvsbL7OhQ2TXr4MJpC6VxahgjACMW1npI0RBuIM=;
        b=A1r4oBN/ntruIl5gBXRNBIbBDvNyRQjZEKNrvkKnrXU+DPwl09vbpuTI0JLz8qbX5f
         JVLBzltM73lrL08PpkPnWWNFrOI9fPI8QG/AbuQmOvfIFnntwnpf2YWhbIGockvjQgzq
         Esp/LrpwSxHVvGUUXPRUSDJpKeO8DgweTNSHCHPfjkGFT7/0ORVKZVJ8Qv18GgntWtjQ
         8LwKS2Nbc+lx8LCZ3vzeQEIHfXboMh00Vx/gjcb4pFBFpl5ZI7oWME4cjxCDA4FF+hgj
         ONzCiRF90Y9pFkqTXNGrwNDXo2D7uaB8JlpYLWxwboEqiZ5unJOjnpXNW6g/TOPIrj1t
         2F6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533K20YEe7ucXUOB60zqrTLQpbcqrUoInlU0WUJ1M7kVvdoY+q+L
	LwdrtVWio9Yjil0LMT4/7Jk=
X-Google-Smtp-Source: ABdhPJwha2QirgQKWBR25n2LqnUCSveDurcufGh2jK1ZV5v46giqByuLvI7TEwdAPi+jzSJTNu+RxQ==
X-Received: by 2002:a05:6808:308e:: with SMTP id bl14mr14886957oib.56.1636124812071;
        Fri, 05 Nov 2021 08:06:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1aa8:: with SMTP id bm40ls1574611oib.6.gmail; Fri,
 05 Nov 2021 08:06:51 -0700 (PDT)
X-Received: by 2002:a05:6808:1408:: with SMTP id w8mr22416620oiv.80.1636124811547;
        Fri, 05 Nov 2021 08:06:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1636124811; cv=none;
        d=google.com; s=arc-20160816;
        b=Yxa4kSu8RPPaV5JI55i6Nvy1f9GvBUT/SjLu7pexdQYuFgfbKCwob8dLwb2gtNSWfG
         akExUpIBNHOi+Lks4apSiMZj3PyfADqql1TFdhww/Q+9I1pOtA1GWCGTqMotoWLcqoCU
         wjnitTRG1pm1fw0HgbIdpNBVRIn1LLk2ACbsZFDyrSxO4/VJQgdof7el7ziYZ155RVTU
         0OcuLnXuvaKgW1TzJ1Zgq4EJL9UANuglae1cs0xierffXmREqp02wdNkhjzmF8Dqkq1M
         9YYZWTeA1L3XjNT6sGnnuok1X4mHdfvzUUg87JFlYAtndNqFdrWXkuTAT/bYg9aKEIfk
         gmFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=N/XGvxinYfHMqC8ASpNZ0TKaYbQ/o6kLCUX0kgvUPGU=;
        b=U3Lz1m64D2GsSB4WLV/3o1EhlKu+HULDrH1AnmRT65BH+zok+uE+AyTTmrHSwcqlOj
         brtPezqZlFhfQ0fUz45PYu0G13D0d8sJBa1C7VpXbetD1cp542T9+xgv+n8377piR3eO
         zduhcJ38hutYQU2/u00r24WhggkQQEA51g6jQNatwzVKdTBSKUXFo12eoNCB4rgoPZTF
         Y+S1WR3kDhWmRvzzCzghVNXtLMlpGWFZc7XoOXml4j4fMIeRHaIKGjXz2F6R06aI18j0
         JlbKmRvpnJfcJypB6+AjLnw3I3PQLvwbANuneHmUjgTr0g4W78Bw+noJTyikrpipFCgT
         grBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=w5k1KDtd;
       spf=pass (google.com: domain of quic_qiancai@quicinc.com designates 129.46.98.28 as permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from alexa-out.qualcomm.com (alexa-out.qualcomm.com. [129.46.98.28])
        by gmr-mx.google.com with ESMTPS id e30si665331ook.2.2021.11.05.08.06.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Nov 2021 08:06:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_qiancai@quicinc.com designates 129.46.98.28 as permitted sender) client-ip=129.46.98.28;
Received: from ironmsg08-lv.qualcomm.com ([10.47.202.152])
  by alexa-out.qualcomm.com with ESMTP; 05 Nov 2021 08:06:50 -0700
X-QCInternal: smtphost
Received: from nasanex01c.na.qualcomm.com ([10.47.97.222])
  by ironmsg08-lv.qualcomm.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Nov 2021 08:06:49 -0700
Received: from nalasex01a.na.qualcomm.com (10.47.209.196) by
 nasanex01c.na.qualcomm.com (10.47.97.222) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.922.7;
 Fri, 5 Nov 2021 08:06:49 -0700
Received: from qian-HP-Z2-SFF-G5-Workstation.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.922.7;
 Fri, 5 Nov 2021 08:06:47 -0700
From: Qian Cai <quic_qiancai@quicinc.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>
CC: Mike Rapoport <rppt@kernel.org>, Andrew Morton
	<akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Russell King
	<linux@armlinux.org.uk>, <kasan-dev@googlegroups.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, Qian Cai <quic_qiancai@quicinc.com>
Subject: [PATCH v2] arm64: Track no early_pgtable_alloc() for kmemleak
Date: Fri, 5 Nov 2021 11:05:09 -0400
Message-ID: <20211105150509.7826-1-quic_qiancai@quicinc.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-Original-Sender: quic_qiancai@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcdkim header.b=w5k1KDtd;       spf=pass
 (google.com: domain of quic_qiancai@quicinc.com designates 129.46.98.28 as
 permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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

After switched page size from 64KB to 4KB on several arm64 servers here,
kmemleak starts to run out of early memory pool due to a huge number of
those early_pgtable_alloc() calls:

  kmemleak_alloc_phys()
  memblock_alloc_range_nid()
  memblock_phys_alloc_range()
  early_pgtable_alloc()
  init_pmd()
  alloc_init_pud()
  __create_pgd_mapping()
  __map_memblock()
  paging_init()
  setup_arch()
  start_kernel()

Increased the default value of DEBUG_KMEMLEAK_MEM_POOL_SIZE by 4 times
won't be enough for a server with 200GB+ memory. There isn't much
interesting to check memory leaks for those early page tables and those
early memory mappings should not reference to other memory. Hence, no
kmemleak false positives, and we can safely skip tracking those early
allocations from kmemleak like we did in the commit fed84c785270
("mm/memblock.c: skip kmemleak for kasan_init()") without needing to
introduce complications to automatically scale the value depends on the
runtime memory size etc. After the patch, the default value of
DEBUG_KMEMLEAK_MEM_POOL_SIZE becomes sufficient again.

Signed-off-by: Qian Cai <quic_qiancai@quicinc.com>
---
v2:
Rename MEMBLOCK_ALLOC_KASAN to MEMBLOCK_ALLOC_NOLEAKTRACE to deal with
those situations in general.

 arch/arm/mm/kasan_init.c   | 2 +-
 arch/arm64/mm/kasan_init.c | 5 +++--
 arch/arm64/mm/mmu.c        | 3 ++-
 include/linux/memblock.h   | 2 +-
 mm/memblock.c              | 9 ++++++---
 5 files changed, 13 insertions(+), 8 deletions(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 4b1619584b23..5ad0d6c56d56 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -32,7 +32,7 @@ pmd_t tmp_pmd_table[PTRS_PER_PMD] __page_aligned_bss;
 static __init void *kasan_alloc_block(size_t size)
 {
 	return memblock_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
-				      MEMBLOCK_ALLOC_KASAN, NUMA_NO_NODE);
+				      MEMBLOCK_ALLOC_NOLEAKTRACE, NUMA_NO_NODE);
 }
 
 static void __init kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 6f5a6fe8edd7..c12cd700598f 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -36,7 +36,7 @@ static phys_addr_t __init kasan_alloc_zeroed_page(int node)
 {
 	void *p = memblock_alloc_try_nid(PAGE_SIZE, PAGE_SIZE,
 					      __pa(MAX_DMA_ADDRESS),
-					      MEMBLOCK_ALLOC_KASAN, node);
+					      MEMBLOCK_ALLOC_NOLEAKTRACE, node);
 	if (!p)
 		panic("%s: Failed to allocate %lu bytes align=0x%lx nid=%d from=%llx\n",
 		      __func__, PAGE_SIZE, PAGE_SIZE, node,
@@ -49,7 +49,8 @@ static phys_addr_t __init kasan_alloc_raw_page(int node)
 {
 	void *p = memblock_alloc_try_nid_raw(PAGE_SIZE, PAGE_SIZE,
 						__pa(MAX_DMA_ADDRESS),
-						MEMBLOCK_ALLOC_KASAN, node);
+						MEMBLOCK_ALLOC_NOLEAKTRACE,
+						node);
 	if (!p)
 		panic("%s: Failed to allocate %lu bytes align=0x%lx nid=%d from=%llx\n",
 		      __func__, PAGE_SIZE, PAGE_SIZE, node,
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index d77bf06d6a6d..acfae9b41cc8 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -96,7 +96,8 @@ static phys_addr_t __init early_pgtable_alloc(int shift)
 	phys_addr_t phys;
 	void *ptr;
 
-	phys = memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
+	phys = memblock_phys_alloc_range(PAGE_SIZE, PAGE_SIZE, 0,
+					 MEMBLOCK_ALLOC_NOLEAKTRACE);
 	if (!phys)
 		panic("Failed to allocate page table page\n");
 
diff --git a/include/linux/memblock.h b/include/linux/memblock.h
index 7df557b16c1e..8adcf1fa8096 100644
--- a/include/linux/memblock.h
+++ b/include/linux/memblock.h
@@ -389,7 +389,7 @@ static inline int memblock_get_region_node(const struct memblock_region *r)
 /* Flags for memblock allocation APIs */
 #define MEMBLOCK_ALLOC_ANYWHERE	(~(phys_addr_t)0)
 #define MEMBLOCK_ALLOC_ACCESSIBLE	0
-#define MEMBLOCK_ALLOC_KASAN		1
+#define MEMBLOCK_ALLOC_NOLEAKTRACE	1
 
 /* We are using top down, so it is safe to use 0 here */
 #define MEMBLOCK_LOW_LIMIT 0
diff --git a/mm/memblock.c b/mm/memblock.c
index 659bf0ffb086..1018e50566f3 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -287,7 +287,7 @@ static phys_addr_t __init_memblock memblock_find_in_range_node(phys_addr_t size,
 {
 	/* pump up @end */
 	if (end == MEMBLOCK_ALLOC_ACCESSIBLE ||
-	    end == MEMBLOCK_ALLOC_KASAN)
+	    end == MEMBLOCK_ALLOC_NOLEAKTRACE)
 		end = memblock.current_limit;
 
 	/* avoid allocating the first page */
@@ -1387,8 +1387,11 @@ phys_addr_t __init memblock_alloc_range_nid(phys_addr_t size,
 	return 0;
 
 done:
-	/* Skip kmemleak for kasan_init() due to high volume. */
-	if (end != MEMBLOCK_ALLOC_KASAN)
+	/*
+	 * Skip kmemleak for those places like kasan_init() and
+	 * early_pgtable_alloc() due to high volume.
+	 */
+	if (end != MEMBLOCK_ALLOC_NOLEAKTRACE)
 		/*
 		 * The min_count is set to 0 so that memblock allocated
 		 * blocks are never reported as leaks. This is because many
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211105150509.7826-1-quic_qiancai%40quicinc.com.
