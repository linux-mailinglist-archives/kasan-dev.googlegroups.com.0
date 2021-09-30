Return-Path: <kasan-dev+bncBDOY5FWKT4KRBF4O3CFAMGQEELGL3QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F3DD41E184
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 20:51:05 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 41-20020a17090a0fac00b00195a5a61ab8sf4613516pjz.3
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 11:51:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633027864; cv=pass;
        d=google.com; s=arc-20160816;
        b=ceGwecEyfSRD9DRyAizX+j76IqnhiUSGwWfrSQzgvHoQDGl38CDgp9a5txUv5gOoQY
         3mfmR5uQGoVlgdRVZJmyQig9NDAnaFs+Dq7dSu8+9GMHI1YOL+dIGlZPDjaa9S6DD1YT
         VgaftWWt8uQ7IWiJWi9HIkgwqQ+5kVU2Nyl5FcCUwB23Ho+npr0oJaIKX1U3jGBIfoLd
         sGppvOKGXZuo2/Ah4/ySPrufAIhuQ3jZ0g56qQlXBu/5Jb16ZNnkK9PSPB9ikyXm7PZ5
         Rabh3l5HHZxQBc5Yl9/XrpRugW18zL3A7m3VY0fQrP3oQgtM8bsTwf4d+4Yfmd4LS7T7
         /YJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GxzaZ0zHNKbE+8WeVVcZnfVtTyerLfGlno4FWUvUOPY=;
        b=TdIlTefNSllSuUPsvUUAHrkA8y03SAGWSGDn2l6UQs1q85rdGy0iiUKSf1WfEAGBcy
         TjoovmAD+A7zOECErxP8s/Nj4HzUPc1m/xivpa8klhzDdP2OsZ3SDUdKAtz0gMKwgK30
         rrt5qlz6saTU/bWMwWyTIqd7kc8PGrUHGyEX97W8QdYPs1/Ej/RU29CoUQcOgEdJY57K
         NeBk+xBNo5b7C2zsl9AZUSdt1NPZlYsdhnG1khlapb7ahFGB0SQh0ATOEu0DgmsH/i7x
         Fj6ND1bVdAvHey0EWr7F8c2iz0vGb7nFQJoMIO41xy/I1vi4CjaRGzwSU/Xs97llE+bB
         K+zA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="rhARG/us";
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GxzaZ0zHNKbE+8WeVVcZnfVtTyerLfGlno4FWUvUOPY=;
        b=Ydr+lCoGfBs0YUymHqTEzOUh12uBYbYda1iLFOTTS4rGwG0HnWA9s2SIn5PDkLAplh
         mjLWTElLz9xGmGIe4JwobsSInXuuFW+v5bfJxDnnOiqnf6auZgi14MNG1Q8ZpZX6gmfL
         WXEdOL8TzqnDAHHwv2DTF5dcQlg3sKl4zwTiyFP12LI1eEyxm4P+TMkSNbdnqQIj7KMW
         mnIbaV9c5z7JmdGOAu9IcmWz2dBYSwFUMRZOPbXx+H3ABmfKGKnJyLCFcIAvBFo+4xLQ
         L+gdhyVypnZuT59eVB7OvtW6czxhjY8h5Nx2pmeCpuAC6oPw854Gdh6d85KMu5SvkG88
         1DeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GxzaZ0zHNKbE+8WeVVcZnfVtTyerLfGlno4FWUvUOPY=;
        b=aColR29mly7PsAg4KNjvK1YIEPSwEmyFngo3TQ2RKI3/c+/07mKbz2DoIlCEW9+zou
         UfDO/JC0inKfrZlZ5HCY8T8iVfpb2oGZb2nl+6jUbOWhe4xT+XwpFBoY4tIZvU8VCxkP
         tjZ06HfH6yw8Khm7stDFZRtIierOxXDLpcCowpUmuY/kbKxfp2fSLBgJkNqT/6lHzqON
         J55RX31dxvb4ZV5Yhivs77NPXewRjbWuirWMJ1R7JxrgK9qeff3eI2UhFyjXrRa1Bhpw
         ML+G/eX9zONeqJ47dKS8wghudzt5SI4piHDfoR873k6SVvhYslbkFBmvKC+36n30n3EB
         N6kQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531LjlJSulqYdj0MdEuwC3T2uyG+RW1W+F0JtK+BAZdYBn2h2w/h
	lzKDY3QrYomAQdDPxQtHaJI=
X-Google-Smtp-Source: ABdhPJw6oLb7cRotsQGjcQbRjcTfYyvvncuQ9zesyzQv9DehMzQLoh3V+rcMMM/rm3lumrK3Y/fftw==
X-Received: by 2002:aa7:8116:0:b0:44b:e0d1:25e9 with SMTP id b22-20020aa78116000000b0044be0d125e9mr7025367pfi.53.1633027863850;
        Thu, 30 Sep 2021 11:51:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c498:: with SMTP id n24ls3992766plx.0.gmail; Thu, 30
 Sep 2021 11:51:03 -0700 (PDT)
X-Received: by 2002:a17:902:9a97:b0:13e:2da4:8132 with SMTP id w23-20020a1709029a9700b0013e2da48132mr5545604plp.34.1633027863258;
        Thu, 30 Sep 2021 11:51:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633027863; cv=none;
        d=google.com; s=arc-20160816;
        b=tFVucHk5Pqb4LOinjPk+VZ3IcCJhNg78uS3Mc4LCQfzv7VwzeSS5mSplfRuZtNBqaA
         DfTW3tOCo8Qd6eKM4vI1O8Mn0iY5hkr2M70eOJWVn1PZxGsjW+AUGBQLtnaYFFSAwvl6
         KPM+p+in16Ns7kjuQIqFGPckydL3XpmORK7SkIDbM5/ETjpffuKfTWHnXHnQxWkKPHb0
         ZFH6BKehN1YRE07VHqjpofp2cPi083xotyq2pQ2bTHC/W6SAVWuabsrM/i0Z4McOYvHo
         aK0mt+V3pkCzOuH3UOL8bu+33aMUyWAuO+JQOUv9400ePSGNatTyuNOcKBfOUlYTGAWm
         xkCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qGgzOM7TeAjdcBzYF4Z/bcaQjsFldJcUmEZRCFeFBWg=;
        b=SK1qeEmIv7a8cliUZNfP1XO/mYDglz/3eXc6n8sBDR0OzCE0MqFMR5LLluODcEWy36
         l2dkrkKFegvZRkEzvXBEyHFukwQ0g5lNxd/Wew1WbHEcwCtRWuCuddj7UA1ZT1P0BK5e
         3HIAyjiOQguuXe8vxtj/N2nmGDbyD47nmH9CN7yKjmltqbVkuYmSYOdTlT/bWEbwqpNk
         Po2cz8t8IyW8cUqoWjDv8NwHhm78Yd4f0/UeudBK3sIyHlpoqNiVCY3s7/tJiTI+d7Et
         qAObkvrqqHVHLCr4N/HvTGXd5QVwLPvEN5jJ+oUXRjrRq4TtSITy4ccKZerJy0qPE5tI
         5ZuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="rhARG/us";
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v7si774827pjk.3.2021.09.30.11.51.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Sep 2021 11:51:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 89FA66135D;
	Thu, 30 Sep 2021 18:50:56 +0000 (UTC)
From: Mike Rapoport <rppt@kernel.org>
To: linux-kernel@vger.kernel.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Juergen Gross <jgross@suse.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Mike Rapoport <rppt@kernel.org>,
	Mike Rapoport <rppt@linux.ibm.com>,
	Shahab Vahedi <Shahab.Vahedi@synopsys.com>,
	devicetree@vger.kernel.org,
	iommu@lists.linux-foundation.org,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	linux-alpha@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-efi@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-sh@vger.kernel.org,
	linux-snps-arc@lists.infradead.org,
	linux-um@lists.infradead.org,
	linux-usb@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	sparclinux@vger.kernel.org,
	xen-devel@lists.xenproject.org
Subject: [PATCH v2 3/6] memblock: drop memblock_free_early_nid() and memblock_free_early()
Date: Thu, 30 Sep 2021 21:50:28 +0300
Message-Id: <20210930185031.18648-4-rppt@kernel.org>
X-Mailer: git-send-email 2.28.0
In-Reply-To: <20210930185031.18648-1-rppt@kernel.org>
References: <20210930185031.18648-1-rppt@kernel.org>
MIME-Version: 1.0
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="rhARG/us";       spf=pass
 (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Mike Rapoport <rppt@linux.ibm.com>

memblock_free_early_nid() is unused and memblock_free_early() is an alias
for memblock_free().

Replace calls to memblock_free_early() with calls to memblock_free() and
remove memblock_free_early() and memblock_free_early_nid().

Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>
---
 arch/mips/mm/init.c                  |  2 +-
 arch/powerpc/platforms/pseries/svm.c |  3 +--
 arch/s390/kernel/smp.c               |  2 +-
 drivers/base/arch_numa.c             |  2 +-
 drivers/s390/char/sclp_early.c       |  2 +-
 include/linux/memblock.h             | 12 ------------
 kernel/dma/swiotlb.c                 |  2 +-
 lib/cpumask.c                        |  2 +-
 mm/percpu.c                          |  8 ++++----
 mm/sparse.c                          |  2 +-
 10 files changed, 12 insertions(+), 25 deletions(-)

diff --git a/arch/mips/mm/init.c b/arch/mips/mm/init.c
index 19347dc6bbf8..21a5a7ac0037 100644
--- a/arch/mips/mm/init.c
+++ b/arch/mips/mm/init.c
@@ -529,7 +529,7 @@ static void * __init pcpu_fc_alloc(unsigned int cpu, size_t size,
 
 static void __init pcpu_fc_free(void *ptr, size_t size)
 {
-	memblock_free_early(__pa(ptr), size);
+	memblock_free(__pa(ptr), size);
 }
 
 void __init setup_per_cpu_areas(void)
diff --git a/arch/powerpc/platforms/pseries/svm.c b/arch/powerpc/platforms/pseries/svm.c
index 87f001b4c4e4..f12229ce7301 100644
--- a/arch/powerpc/platforms/pseries/svm.c
+++ b/arch/powerpc/platforms/pseries/svm.c
@@ -56,8 +56,7 @@ void __init svm_swiotlb_init(void)
 		return;
 
 
-	memblock_free_early(__pa(vstart),
-			    PAGE_ALIGN(io_tlb_nslabs << IO_TLB_SHIFT));
+	memblock_free(__pa(vstart), PAGE_ALIGN(io_tlb_nslabs << IO_TLB_SHIFT));
 	panic("SVM: Cannot allocate SWIOTLB buffer");
 }
 
diff --git a/arch/s390/kernel/smp.c b/arch/s390/kernel/smp.c
index 1a04e5bdf655..066efd6d9345 100644
--- a/arch/s390/kernel/smp.c
+++ b/arch/s390/kernel/smp.c
@@ -880,7 +880,7 @@ void __init smp_detect_cpus(void)
 
 	/* Add CPUs present at boot */
 	__smp_rescan_cpus(info, true);
-	memblock_free_early((unsigned long)info, sizeof(*info));
+	memblock_free((unsigned long)info, sizeof(*info));
 }
 
 /*
diff --git a/drivers/base/arch_numa.c b/drivers/base/arch_numa.c
index f6d0efd01188..e28d9dfe3c20 100644
--- a/drivers/base/arch_numa.c
+++ b/drivers/base/arch_numa.c
@@ -165,7 +165,7 @@ static void * __init pcpu_fc_alloc(unsigned int cpu, size_t size,
 
 static void __init pcpu_fc_free(void *ptr, size_t size)
 {
-	memblock_free_early(__pa(ptr), size);
+	memblock_free(__pa(ptr), size);
 }
 
 void __init setup_per_cpu_areas(void)
diff --git a/drivers/s390/char/sclp_early.c b/drivers/s390/char/sclp_early.c
index f3d5c7f4c13d..f01d942e1c1d 100644
--- a/drivers/s390/char/sclp_early.c
+++ b/drivers/s390/char/sclp_early.c
@@ -139,7 +139,7 @@ int __init sclp_early_get_core_info(struct sclp_core_info *info)
 	}
 	sclp_fill_core_info(info, sccb);
 out:
-	memblock_free_early((unsigned long)sccb, length);
+	memblock_free((unsigned long)sccb, length);
 	return rc;
 }
 
diff --git a/include/linux/memblock.h b/include/linux/memblock.h
index 34de69b3b8ba..fc8183be340c 100644
--- a/include/linux/memblock.h
+++ b/include/linux/memblock.h
@@ -441,18 +441,6 @@ static inline void *memblock_alloc_node(phys_addr_t size,
 				      MEMBLOCK_ALLOC_ACCESSIBLE, nid);
 }
 
-static inline void memblock_free_early(phys_addr_t base,
-					      phys_addr_t size)
-{
-	memblock_free(base, size);
-}
-
-static inline void memblock_free_early_nid(phys_addr_t base,
-						  phys_addr_t size, int nid)
-{
-	memblock_free(base, size);
-}
-
 static inline void memblock_free_late(phys_addr_t base, phys_addr_t size)
 {
 	__memblock_free_late(base, size);
diff --git a/kernel/dma/swiotlb.c b/kernel/dma/swiotlb.c
index 87c40517e822..430d2f78d540 100644
--- a/kernel/dma/swiotlb.c
+++ b/kernel/dma/swiotlb.c
@@ -247,7 +247,7 @@ swiotlb_init(int verbose)
 	return;
 
 fail_free_mem:
-	memblock_free_early(__pa(tlb), bytes);
+	memblock_free(__pa(tlb), bytes);
 fail:
 	pr_warn("Cannot allocate buffer");
 }
diff --git a/lib/cpumask.c b/lib/cpumask.c
index c3c76b833384..045779446a18 100644
--- a/lib/cpumask.c
+++ b/lib/cpumask.c
@@ -188,7 +188,7 @@ EXPORT_SYMBOL(free_cpumask_var);
  */
 void __init free_bootmem_cpumask_var(cpumask_var_t mask)
 {
-	memblock_free_early(__pa(mask), cpumask_size());
+	memblock_free(__pa(mask), cpumask_size());
 }
 #endif
 
diff --git a/mm/percpu.c b/mm/percpu.c
index e0a986818903..f58318cb04c0 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -2472,7 +2472,7 @@ struct pcpu_alloc_info * __init pcpu_alloc_alloc_info(int nr_groups,
  */
 void __init pcpu_free_alloc_info(struct pcpu_alloc_info *ai)
 {
-	memblock_free_early(__pa(ai), ai->__ai_size);
+	memblock_free(__pa(ai), ai->__ai_size);
 }
 
 /**
@@ -3134,7 +3134,7 @@ int __init pcpu_embed_first_chunk(size_t reserved_size, size_t dyn_size,
 out_free:
 	pcpu_free_alloc_info(ai);
 	if (areas)
-		memblock_free_early(__pa(areas), areas_size);
+		memblock_free(__pa(areas), areas_size);
 	return rc;
 }
 #endif /* BUILD_EMBED_FIRST_CHUNK */
@@ -3256,7 +3256,7 @@ int __init pcpu_page_first_chunk(size_t reserved_size,
 		free_fn(page_address(pages[j]), PAGE_SIZE);
 	rc = -ENOMEM;
 out_free_ar:
-	memblock_free_early(__pa(pages), pages_size);
+	memblock_free(__pa(pages), pages_size);
 	pcpu_free_alloc_info(ai);
 	return rc;
 }
@@ -3286,7 +3286,7 @@ static void * __init pcpu_dfl_fc_alloc(unsigned int cpu, size_t size,
 
 static void __init pcpu_dfl_fc_free(void *ptr, size_t size)
 {
-	memblock_free_early(__pa(ptr), size);
+	memblock_free(__pa(ptr), size);
 }
 
 void __init setup_per_cpu_areas(void)
diff --git a/mm/sparse.c b/mm/sparse.c
index 120bc8ea5293..55fea0c2f927 100644
--- a/mm/sparse.c
+++ b/mm/sparse.c
@@ -451,7 +451,7 @@ static void *sparsemap_buf_end __meminitdata;
 static inline void __meminit sparse_buffer_free(unsigned long size)
 {
 	WARN_ON(!sparsemap_buf || size == 0);
-	memblock_free_early(__pa(sparsemap_buf), size);
+	memblock_free(__pa(sparsemap_buf), size);
 }
 
 static void __init sparse_buffer_init(unsigned long size, int nid)
-- 
2.28.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210930185031.18648-4-rppt%40kernel.org.
