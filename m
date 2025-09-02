Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB44H3TCQMGQER6PALXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id DC041B40791
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:49:25 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-7723aca1cbcsf2900230b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:49:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824564; cv=pass;
        d=google.com; s=arc-20240605;
        b=UJp4OqHJf5yC4m0cKmfLiCJNFSBmwuhMjvB+qO7qlIO641l0qtYJ5n8PO4ZGDUWxid
         dSdU8aHMQQ7neNx1dyfsuRzZ1P5J2FDjTfT7ew4MCQ1CHFXXAuvloFEooOCyRIPxjBXl
         R61L/vtXYh8nlMOdNadnDzisO4vJfsdONNvfkYvzyRdilhxpZNDrYLdFogzGOfOwmhJ4
         HWZwu7J1AlriiECcbt7VTOwt2ofGwD5Y8UpoJZ/hphJw39R5mM5ciu+lYIafh2QaSsKS
         BRgy7VBRai3VusFAuPcHuGbd90zxnR2OTCxbZsrot+lPbDsD3PFCUNu0ndDJ2jajAPfY
         1jEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=kq4RzOZ0DaI7tE1pzWCzg39ebHeGOMMQ7XZcvBBv2sI=;
        fh=QZvB6PaWQQiTX5m9gImwo1ROjvCGJTL4nzJ8U8sUuaI=;
        b=eo7PrZQhJmKuPKdJTmF8plhK1gNRmCg4+QDB/WGK7D1o50PXvnB7xerRGVSnucfVYb
         yBufVoH1EAYRmBT1RDjFl5qv1Uk47JVj7VgdS+kzic5cdcsZUnuyaFrvnYqLwSIQvOFl
         5DwjRkqoVORIoVLceyo9tTgvZ2/6Q/VpHuDuZQOnGKzEjYsV1yhcY05tyAng7gsDuXcw
         zuJAeCGdATI3BZTWFbfzImmlHEkQ9FWUyy8pdhX1GC+uyeYBBRRKi3F+6MCZs7lyieYa
         tjKsXqmOKCrO4Sbqub8VTjGFtvDyC30x8tixhlm7UuyvNclwf05A0w+XadG6Chtz3cvv
         /XRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="myJAVWf/";
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824564; x=1757429364; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kq4RzOZ0DaI7tE1pzWCzg39ebHeGOMMQ7XZcvBBv2sI=;
        b=aEplc4iCe4AfgenTY2gruZMpZyf0AHEHWJ5X4J6baib3fm9l/SPLw2uzmAjkrg0xid
         HAZyQlGu3kc1F/O5t5clHHFjz2SVXcM/wpwsirM3ip0L6AOrZtNZ/xkbxXTqAMDX7CdA
         dUS3IeCaH0oAnmnnG89hWI024p7bUcYkVHlLTglNQ00eDcTthyvwtx4YVrWdP+FORFET
         sEVyTqcfi7ZrYS2a7IdfOXOKeQhR9iy2QTj3knP9iegEejlcz6xIPmoslUmGO7Yf12B3
         m1mhMiOS/ak55CdCObbTJuuhEASyO1E/1IiRFpZoByb4q+YNK4Mcgbu32RJb2mKLvWC3
         YveA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824564; x=1757429364;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kq4RzOZ0DaI7tE1pzWCzg39ebHeGOMMQ7XZcvBBv2sI=;
        b=QrmTAaQkh3eFrGq8iaOdD1Lf6resGVkkyqZQ+RcXt/uFTOVscpx083aSgqXA2EnGxc
         YUQ+26IpGpNVur7Tf9aI3H0J7NeB+EShlvr50Csi+v78LKxmb7cdfyRQlqn7sIySPHhv
         o7ppIKKHcAVsamQQDZedQGRsbP+NKriPVa9ltJzIFjZ1xKygRify9cmrbdwMvVeGOx9B
         frTMgvjdEVGXa7qBfVdYh1IUiFfCo0LugaMGWsa7mLt+74qz+8hdWIDhsJMO/YbzHsq6
         /5V04HXti3PfbqFmcSMjjMbSzKLq9G8/5HVZzvs6v2cdIP6JLgDBXYTLhIjGbT9Q63HN
         tkRw==
X-Forwarded-Encrypted: i=2; AJvYcCU3Gmxul62lJjch30l0o1MWtDgvBsgUKvIq+INuPMOVZGOkvvOuL0IUJv8gRho+6y1KUTyFKQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywk5pEmCUv9DCMoWeANQR7dkZfTJmsbE1IHqfWQAuhGr/dW9QkJ
	Zvcwlohy337FgD5ElZC8dEhBXSOO9liL9ZOGcVWQtAuK6cs/nRecwQH4
X-Google-Smtp-Source: AGHT+IGJB0mcqixM+CMmqs8XcCVpOdHGI2DdrcQdE+z6cXouFgzh7X4b8N1F6FB7caGyfEPMN1LjUA==
X-Received: by 2002:a05:6a00:3d09:b0:772:59c6:433a with SMTP id d2e1a72fcca58-77259c650ebmr10593460b3a.24.1756824564199;
        Tue, 02 Sep 2025 07:49:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeKJ2wKf5ZQvy7YrAj7oYfCsltfQ0EHllnDcKsOdjlCHQ==
Received: by 2002:a05:6a00:3cc6:b0:772:50c7:d04d with SMTP id
 d2e1a72fcca58-77250c7d27els2908306b3a.1.-pod-prod-04-us; Tue, 02 Sep 2025
 07:49:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUaSM7pWiAH/UKkD+2G4FycQWJM+4C08fIaLzD8l3izogaj1XOWTZRwzc4dQiI0lIDnmIIFJWfVVLQ=@googlegroups.com
X-Received: by 2002:a05:6a21:33a7:b0:243:b5eb:9cff with SMTP id adf61e73a8af0-243d6f3814fmr16796302637.41.1756824562822;
        Tue, 02 Sep 2025 07:49:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824562; cv=none;
        d=google.com; s=arc-20240605;
        b=Cbz1womd/mrdKeGojpXHsAMNnGzFQYebdzn+61MplDj4ymra4s8CGjfpTydJykkXEH
         S1d1OuFbR3YeIqVDmxLiaLeNt1txe4PVmdhxG9I7lAtJujcPDlOieU1b4BfwVI1Nryhv
         2WFGUXgc1vn7peN7YIJTjk+p2F+qqJ0rUCdKC5TNj2Opy6DwrKt8SYqDDfT6KWcty0qj
         eWoK5NU+bLVANxF1tkY2CcNqHXu5f4hg3hqA4EcNaaqC/5MOW81QiOaMhEk+ry+ExuBU
         bHOfVlm+uD8dDU1ECrmeeFVpNxMP6zwk2H4qS69VlK4X9E/aKdOtooFi7uyBhwE8is+G
         iY9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0r28goZFSxu4+TQiPbsxYpHpPmrnbh7KwEU70GjOWDk=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=EbfORpd4Wp0oE+JaHdqx07f/rci+dZw+sfTWXJlV4V/ElIqtZCVhMbaqtd8Jgf/lr9
         u7ykYVrBDW/MPUp0evBn4t/qkgKSPYh98PwXlXq6C+nRFbi+jrQ7ZLghV3veCKuGJJjl
         LwArbJqsZxfdgWbCvxYUROAOU697cn+JpIwsxFn612PbjSW1VVtzz3WpTwiotYYvfZsF
         GCE64Tm3aVBUsmcSc62Y7jkAqlT2B+nHCFf3rwl4l3lPegDxZt4UUfocG1kOOJz1ZoAL
         KkT9njzgOYkRQcMuOEsWalo4WisG/TCteIZdrodniMWixsEUURwjOwSQ7A9PV1eVAgjF
         6TuQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="myJAVWf/";
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4e861f79bbsi318816a12.0.2025.09.02.07.49.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:49:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 997C144B04;
	Tue,  2 Sep 2025 14:49:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 63F72C4CEED;
	Tue,  2 Sep 2025 14:49:21 +0000 (UTC)
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
	David Hildenbrand <david@redhat.com>,
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
Subject: [PATCH v5 05/16] iommu/dma: rename iommu_dma_*map_page to iommu_dma_*map_phys
Date: Tue,  2 Sep 2025 17:48:42 +0300
Message-ID: <9b7eebd170d68db9854056e24b94ec1fdad73d6f.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="myJAVWf/";       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c | 14 ++++++--------
 include/linux/iommu-dma.h |  7 +++----
 kernel/dma/mapping.c      |  4 ++--
 kernel/dma/ops_helpers.c  |  6 +++---
 4 files changed, 14 insertions(+), 17 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index e1185ba73e23..aea119f32f96 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1195,11 +1195,9 @@ static inline size_t iova_unaligned(struct iova_domain *iovad, phys_addr_t phys,
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
@@ -1227,7 +1225,7 @@ dma_addr_t iommu_dma_map_page(struct device *dev, struct page *page,
 	return iova;
 }
 
-void iommu_dma_unmap_page(struct device *dev, dma_addr_t dma_handle,
+void iommu_dma_unmap_phys(struct device *dev, dma_addr_t dma_handle,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
 	struct iommu_domain *domain = iommu_get_dma_domain(dev);
@@ -1346,7 +1344,7 @@ static void iommu_dma_unmap_sg_swiotlb(struct device *dev, struct scatterlist *s
 	int i;
 
 	for_each_sg(sg, s, nents, i)
-		iommu_dma_unmap_page(dev, sg_dma_address(s),
+		iommu_dma_unmap_phys(dev, sg_dma_address(s),
 				sg_dma_len(s), dir, attrs);
 }
 
@@ -1359,8 +1357,8 @@ static int iommu_dma_map_sg_swiotlb(struct device *dev, struct scatterlist *sg,
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
index 508beaa44c39..485bdffed988 100644
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
index fe1f0da6dc50..58482536db9b 100644
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
index 9afd569eadb9..6f9d604d9d40 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9b7eebd170d68db9854056e24b94ec1fdad73d6f.1756822782.git.leon%40kernel.org.
