Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBCOWYLCAMGQEMSDR2BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id EE5FCB1A1B6
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:43:55 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-23824a9bc29sf57635815ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:43:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311434; cv=pass;
        d=google.com; s=arc-20240605;
        b=NaLymTV/37eTutos10lN7d4CE0CT5dVvY87WVIWGYF5UGzCwSe+zoWbxXe0TcMg4QJ
         X9pi2YPewTPdTKjEbFU3UMBgJIExbE4YY1zgOhN7WpNtJiM0siftHgNSwyQbGLiKoxhV
         wF1ZRcIbdgDs1RHCEkXuWA1Md+OxR4E+l0VkHKleDv167TS3cuvMyeO6/2yX4oBWWsgh
         cwRBX2pi+YWxscyVGpQEXJ4KqqCyrOgIeio3znyjbtyEbmpiFIPYFH/xpEd1v7MZQz/U
         hQXwRPdhLW3RtTqhn/uXRyvKmrDkWN+b34s8HbVVuBTeRiahJXbRyv86bEg02PIbq83z
         nG1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=B1X+3RGFWy8llIWX4nIWvRER0I7zQxZFx0fccm8CaTE=;
        fh=adS+tXdvu82spZHHNxFj6aQn8fCz4q7w3NYBOnJ2Qqo=;
        b=Dh8NZ4fptwOgX58q2Ohbgfn0bAZOUce96YloRh+JSftYX5CXn2y81H6y/Y0agBvvjr
         BBk63+ZyHUx3m5MifE6woO+BvEQrF5/111d803I/Qj4RhDKdiYSl+etG9itLAhW8qDIy
         bzWOd2JR6JYZD2aeGEMLGtMv+y7vU5G+09+vWXf7i7INufPgM44vNbnFqGfpTOy18/M/
         KZKZcd0wCPTd+iKEZnU/nRWqU4i4gHemn+Cj8rjW3d+TLHAsdQ0VpH107zqz88wMsnfb
         af1d7oj0u9E8vXf3ewBXG6oNARL4GTr0jA/lcqmIQTM6UF9+Qp/hJ2h/F4QJC8NTyBBT
         vAjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Aa0MuxNB;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311434; x=1754916234; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=B1X+3RGFWy8llIWX4nIWvRER0I7zQxZFx0fccm8CaTE=;
        b=ftRR7akx6VhV7ixbXO5dH8tnokOdkWJ/QZF6WuF4BO26FkmAW037PT/DxWPEVSVLB/
         M/YSsQs4ffKV8Yj4BB2bjVS/JO5K4hrBmfKtrNCqbedZ+x9pwaBBJIYs6HA+S/IACLfk
         UcDaXgXWQPcBZ81tGAIRjHDOvBtNZQRaMchLKksybWBwOXjvmH1FYGmYN1ibGyFW3qxC
         CRxzLsyT3HJ/8qSfboyhqDY5CNa4B2IYJ+UYe+XyrJHS1UCuv3Ne+XGYPCK1Q6bn3yZr
         UGUpfxGpG5fzPr4wzh1iRhhN9sgNYsnIdGlq9z4MC8eBdU/t5KRpxBRdCHdcwN+XnOuF
         qAHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311434; x=1754916234;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=B1X+3RGFWy8llIWX4nIWvRER0I7zQxZFx0fccm8CaTE=;
        b=i1+PUOdXHHjdiDhXXcRjEkrwMyO8rkSZT96DhgVzK7EGM+6ip8etxSWMxm1M2CmAdJ
         +K7Wj89yVs7lK/7jaOWF4m//eWiDRBXJAyefVVh94NTbY8/QFHKGwFdqq+AA2X2mzOJJ
         1M8AVJCgM06h/m5k74KmMxDJFk7BRmfavMCMCgivkWyJ6XoGjE12IDuyFYWRMrfgJTIG
         Ms6Hghs0z8KSIOk2gxymlDasyasXt1AUcl2kKxxKKGjAMeyKWYWo2Cb/O1tKyqW3P+Ae
         9qwqYLz1cVgchK4s5C7OJMmH++M5kRv4ylXtWlhbJtk00tp4fftGtxjoSSr/qwMM/Csu
         KCIg==
X-Forwarded-Encrypted: i=2; AJvYcCWIrFb+0KfKbEHURJirVbVPNQQ7glZoYEnBA0PArnP8tf5HPtTVsBka412RWLIQJu5hJs9E3w==@lfdr.de
X-Gm-Message-State: AOJu0YySPpOPf/EDuKOXUIWXM3mIHNCJGhxIUxUJKFEoCbN+wWw/vG2j
	1IL9P+9tKoARGZG2uTkWbP/7DNlbYCWz1vwoRSqybTDiYYzzDXTjgNIF
X-Google-Smtp-Source: AGHT+IFGrZUWasXaMoFXIPlwOoohqx7bjsJUtBpmmqwIVt2/SNoqt2CxosPiIYib56pnYJwR7I2z/g==
X-Received: by 2002:a17:902:ce8c:b0:240:aa0:1584 with SMTP id d9443c01a7336-242470302ebmr142729205ad.38.1754311434117;
        Mon, 04 Aug 2025 05:43:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeBErCdswET9xdr1sRMFYB5w1KKYfGKyI2+PofoxyAM/w==
Received: by 2002:a17:90a:e7d1:b0:31e:616e:b40f with SMTP id
 98e67ed59e1d1-31f910f8f4els5382628a91.0.-pod-prod-08-us; Mon, 04 Aug 2025
 05:43:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWK0dg7amdVcJK3I5nXP2+DZIIGMZVNhi5VmM1dwc/VkmQp5X7UHvBqEV8V2BMNaBH6sALwBFTOzI4=@googlegroups.com
X-Received: by 2002:a17:90a:cb94:b0:311:ea13:2e70 with SMTP id 98e67ed59e1d1-32116210496mr11289120a91.14.1754311430643;
        Mon, 04 Aug 2025 05:43:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311430; cv=none;
        d=google.com; s=arc-20240605;
        b=dGCuj2K2sljwfUyS8Wf+Au0aBSMPD7qg8BymAdqqPB3DxYjcPrRF8354AlOPyTp6No
         LeV0mfPKmMYtQVNZ+l1GtJ6QyG+FSFkMIJpsjIf9EfTSmvfWvQ6uHhCmBlcyzwsx21A3
         AX90LbN8CBTB2SoVFLgJT/TcUsUezRNGRPJHnD12SuwV7/dOkNwTke1F441C2mlsEzP5
         WmcxUTJn2TudaTI+SjC6j8t6ireOpqJLi92uoCDaVQ5byt7YSLSmCPFC/bQtmLs+n6L/
         2hkbRICMF0ENmGRuVaanb98YMDd4AX66ZX2mVlxykk6onfbSFQUol5uN+0yhwJvtJZXz
         zxzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aUGRZ8OiFKTYz3bE7TMZcKc2yGhFtaAdl3sZst6yCGU=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=Fljx3GlYgRoN2iRlXYz6hijOHQV4EckBs/gbALrM90pAOPzCwbb3sfgIxqWs/CW4v4
         KDqnxFD2FL71qlqrmgvgsh7IkuimvJhYGr03ROX0aHaId9Ae/S4WVu2kfNXIknXrzgG3
         LKv6o6UlNVTngFcnyJywtmksdYLJwnhdMlbcVj3W9O+XrjJE5FYaFSD9kjDD9rYfy3WE
         rIAHtnjv+xOAonUTIJPkj9rFkfMMG6nRblDMRO+oGPI41NdaAvuUawkrfIWcK2kDyMtJ
         AcPyQjlf9WdBrYqPeQGJBrgikZwhq/nc+AoUzc5pjVlLgE9yP44xlvdUtv+pquyJ/WS1
         Nxpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Aa0MuxNB;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31f63e9d886si615502a91.2.2025.08.04.05.43.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:43:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id DB03EA55869;
	Mon,  4 Aug 2025 12:43:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 77632C4CEF8;
	Mon,  4 Aug 2025 12:43:48 +0000 (UTC)
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leonro@nvidia.com>,
	Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>,
	Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev,
	Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>,
	Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com,
	Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-nvme@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>,
	rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev,
	Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: [PATCH v1 05/16] iommu/dma: rename iommu_dma_*map_page to iommu_dma_*map_phys
Date: Mon,  4 Aug 2025 15:42:39 +0300
Message-ID: <9186ccefda5ea97b56ec006900127650f9e324b5.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Aa0MuxNB;       spf=pass
 (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Leon Romanovsky <leon@kernel.org>
Reply-To: Leon Romanovsky <leon@kernel.org>
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

From: Leon Romanovsky <leonro@nvidia.com>

Rename the IOMMU DMA mapping functions to better reflect their actual
calling convention. The functions iommu_dma_map_page() and
iommu_dma_unmap_page() are renamed to iommu_dma_map_phys() and
iommu_dma_unmap_phys() respectively, as they already operate on physical
addresses rather than page structures.

The calling convention changes from accepting (struct page *page,
unsigned long offset) to (phys_addr_t phys), which eliminates the need
for page-to-physical address conversion within the functions. This
renaming prepares for the broader DMA API conversion from page-based
to physical address-based mapping throughout the kernel.

All callers are updated to pass physical addresses directly, including
dma_map_page_attrs(), scatterlist mapping functions, and DMA page
allocation helpers. The change simplifies the code by removing the
page_to_phys() + offset calculation that was previously done inside
the IOMMU functions.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c | 14 ++++++--------
 include/linux/iommu-dma.h |  7 +++----
 kernel/dma/mapping.c      |  4 ++--
 kernel/dma/ops_helpers.c  |  6 +++---
 4 files changed, 14 insertions(+), 17 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index 399838c17b705..11c5d5f8c0981 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1190,11 +1190,9 @@ static inline size_t iova_unaligned(struct iova_domain *iovad, phys_addr_t phys,
 	return iova_offset(iovad, phys | size);
 }
 
-dma_addr_t iommu_dma_map_page(struct device *dev, struct page *page,
-	      unsigned long offset, size_t size, enum dma_data_direction dir,
-	      unsigned long attrs)
+dma_addr_t iommu_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		enum dma_data_direction dir, unsigned long attrs)
 {
-	phys_addr_t phys = page_to_phys(page) + offset;
 	bool coherent = dev_is_dma_coherent(dev);
 	int prot = dma_info_to_prot(dir, coherent, attrs);
 	struct iommu_domain *domain = iommu_get_dma_domain(dev);
@@ -1222,7 +1220,7 @@ dma_addr_t iommu_dma_map_page(struct device *dev, struct page *page,
 	return iova;
 }
 
-void iommu_dma_unmap_page(struct device *dev, dma_addr_t dma_handle,
+void iommu_dma_unmap_phys(struct device *dev, dma_addr_t dma_handle,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
 	struct iommu_domain *domain = iommu_get_dma_domain(dev);
@@ -1341,7 +1339,7 @@ static void iommu_dma_unmap_sg_swiotlb(struct device *dev, struct scatterlist *s
 	int i;
 
 	for_each_sg(sg, s, nents, i)
-		iommu_dma_unmap_page(dev, sg_dma_address(s),
+		iommu_dma_unmap_phys(dev, sg_dma_address(s),
 				sg_dma_len(s), dir, attrs);
 }
 
@@ -1354,8 +1352,8 @@ static int iommu_dma_map_sg_swiotlb(struct device *dev, struct scatterlist *sg,
 	sg_dma_mark_swiotlb(sg);
 
 	for_each_sg(sg, s, nents, i) {
-		sg_dma_address(s) = iommu_dma_map_page(dev, sg_page(s),
-				s->offset, s->length, dir, attrs);
+		sg_dma_address(s) = iommu_dma_map_phys(dev, sg_phys(s),
+				s->length, dir, attrs);
 		if (sg_dma_address(s) == DMA_MAPPING_ERROR)
 			goto out_unmap;
 		sg_dma_len(s) = s->length;
diff --git a/include/linux/iommu-dma.h b/include/linux/iommu-dma.h
index 508beaa44c39e..485bdffed9888 100644
--- a/include/linux/iommu-dma.h
+++ b/include/linux/iommu-dma.h
@@ -21,10 +21,9 @@ static inline bool use_dma_iommu(struct device *dev)
 }
 #endif /* CONFIG_IOMMU_DMA */
 
-dma_addr_t iommu_dma_map_page(struct device *dev, struct page *page,
-		unsigned long offset, size_t size, enum dma_data_direction dir,
-		unsigned long attrs);
-void iommu_dma_unmap_page(struct device *dev, dma_addr_t dma_handle,
+dma_addr_t iommu_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		enum dma_data_direction dir, unsigned long attrs);
+void iommu_dma_unmap_phys(struct device *dev, dma_addr_t dma_handle,
 		size_t size, enum dma_data_direction dir, unsigned long attrs);
 int iommu_dma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
 		enum dma_data_direction dir, unsigned long attrs);
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index fe1f0da6dc507..58482536db9bb 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -169,7 +169,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 	    arch_dma_map_page_direct(dev, phys + size))
 		addr = dma_direct_map_page(dev, page, offset, size, dir, attrs);
 	else if (use_dma_iommu(dev))
-		addr = iommu_dma_map_page(dev, page, offset, size, dir, attrs);
+		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
 	else
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
 	kmsan_handle_dma(page, offset, size, dir);
@@ -190,7 +190,7 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 	    arch_dma_unmap_page_direct(dev, addr + size))
 		dma_direct_unmap_page(dev, addr, size, dir, attrs);
 	else if (use_dma_iommu(dev))
-		iommu_dma_unmap_page(dev, addr, size, dir, attrs);
+		iommu_dma_unmap_phys(dev, addr, size, dir, attrs);
 	else
 		ops->unmap_page(dev, addr, size, dir, attrs);
 	trace_dma_unmap_phys(dev, addr, size, dir, attrs);
diff --git a/kernel/dma/ops_helpers.c b/kernel/dma/ops_helpers.c
index 9afd569eadb96..6f9d604d9d406 100644
--- a/kernel/dma/ops_helpers.c
+++ b/kernel/dma/ops_helpers.c
@@ -72,8 +72,8 @@ struct page *dma_common_alloc_pages(struct device *dev, size_t size,
 		return NULL;
 
 	if (use_dma_iommu(dev))
-		*dma_handle = iommu_dma_map_page(dev, page, 0, size, dir,
-						 DMA_ATTR_SKIP_CPU_SYNC);
+		*dma_handle = iommu_dma_map_phys(dev, page_to_phys(page), size,
+						 dir, DMA_ATTR_SKIP_CPU_SYNC);
 	else
 		*dma_handle = ops->map_page(dev, page, 0, size, dir,
 					    DMA_ATTR_SKIP_CPU_SYNC);
@@ -92,7 +92,7 @@ void dma_common_free_pages(struct device *dev, size_t size, struct page *page,
 	const struct dma_map_ops *ops = get_dma_ops(dev);
 
 	if (use_dma_iommu(dev))
-		iommu_dma_unmap_page(dev, dma_handle, size, dir,
+		iommu_dma_unmap_phys(dev, dma_handle, size, dir,
 				     DMA_ATTR_SKIP_CPU_SYNC);
 	else if (ops->unmap_page)
 		ops->unmap_page(dev, dma_handle, size, dir,
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9186ccefda5ea97b56ec006900127650f9e324b5.1754292567.git.leon%40kernel.org.
