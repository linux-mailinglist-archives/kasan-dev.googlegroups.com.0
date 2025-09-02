Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB7UH3TCQMGQECNDCSIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id B5D2EB4079E
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:49:35 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4b3200a05dfsf51402951cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:49:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824574; cv=pass;
        d=google.com; s=arc-20240605;
        b=X1fl/mNRIszjc0d79C9lXjT6xozW3s10uDEV44cD0KCaWFzuPdmGejEWv6m2UB4KcG
         /MIdh4eH+hVKtfOTHz02WAbEjv6CxGQxsyd4kPk8BZROAz/Y+olnvb0XFOpx5VjZUsth
         5to2d3cfYUMMJXG+gf75mzpn+r2tLT9ROYpmuJEcmOjEy4vHJ37bMGVznv0oCAbtAnxq
         zeEX9keXX5mosfuhIqq3XmKNTvs7weYByAF5m5KA7+H537QZYVViMoT7YBDoVzfRi2VO
         2c6EugTxopz2+SWvEHzNQCLwNIofwhj8t+6xQkaIuAt7lDNd85GZedN9cnMP8XmABqhm
         lm8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=gt7wrsAuaAcvJWeNMH62xbek9LoaIg3Zpn81ZNyZF3A=;
        fh=nlgHKXosagKQ2QQ4QAvtbEtgWdBMCwFKfPRdMPPLyxc=;
        b=SfmvCTO0zS/p3XF6uhhTOvBjb/YXJYc1awcarJ7ZzEm2z7XQYbAUqq/Q/oRDjRJU6s
         XD8+eYUZoF1t2EWl+zUmBugfobft+GWsKxqf/Ae7Tf+quFs4VfimH3PQtDrsluO/KhuY
         pLJm2bTU4jkE++hi13EdnW8GR1ItYVcFaPiht2BNylyZ1pXIGpInK93R0a8ZQB0KV9+Y
         AWq7K/UqI/1VyClJdFsmB+YEzRvXbYYPQhzl3VwniapIl2UcUutpTSxOlSkr4zb47Lzf
         WgAYGhRnznZ8s8ifM8Tx5uTQnQLXoU/GnFG+zURJ0h+tdU1DjYXgwp5xUDhkKwYqFfyB
         fiaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=agxG7jxN;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824574; x=1757429374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gt7wrsAuaAcvJWeNMH62xbek9LoaIg3Zpn81ZNyZF3A=;
        b=CpnfoBeWJpl8TQfK9Fj5jH+Nt9lF4c0Ezwi8HEUNJVi2XVBjjFyeMfaOoQydxWTQUR
         VJX0D1lOoGEFMxuKCN45PTNZ6Q8ATxf2DC8ZLmlXpjSo9EvodQt/mM6YnJWBU8CcCVcg
         m8o+JH+pJ017r4QsXaVPmPpSanwmGFnkfioWbiiZ3Vx1kN2yZqZd5zMrcgAG9FqDktYS
         R13bK/wJM59QXU2+troIw2FyW+dx9Y0dhXdcW0/2mdx6cxLw4a/GKYemH2PnScVOrmDP
         pn2GPcx0S9JcCCQCFk3/be9/Bu1KcaKQoqy4FWDKYZCn5Ahxbk1LWuO229T6grbyow6R
         daPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824574; x=1757429374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gt7wrsAuaAcvJWeNMH62xbek9LoaIg3Zpn81ZNyZF3A=;
        b=J7aZlFDv3UltqcZHoIgqDwlAySYMWwOQZZWyVkFayl7hct4eyCrpoA5sKOFar0IzN+
         l9C5x9OTBWdgm3jNBAuZ+Rx7HqnNvfwIqLAjQo29lH7XK+udYawEB5eR9GdNDecGXCSD
         WcCHAySaZcv6EY4zJqzKlwjWoTC9AOV60QgYzqKVyGNzFSIA5FL5EdZqXqPIvu5KU9vl
         pTdO+Zi6inxCTdYZCyTe69QTmQWQNCTNQK3X9EDS/Xq/nDDo4zQjwmqhBwyfexE5msUv
         7B65rJExVj5a2t8rDha3SD850JyDK+SHR2BHdjg26FWOaNypipjpqpssWX5Zohc39NgI
         QsRw==
X-Forwarded-Encrypted: i=2; AJvYcCU+AA8/r61mKqvJabpTnrl+Bz1YtSL0Ec5LxNG0t+z5kgP8BdajfFp5JnkBgeE7bVl7BuZReg==@lfdr.de
X-Gm-Message-State: AOJu0Yz/6oIJITsPJLDB81y7oLA/of+7+Z+QP+B7L7iv8tZKeI6nXKHN
	Hy5HgRV23pOwOfso7sx2eRWy5OQNx8754qt6Ec9Nxi8/t0LpN2TVDr7K
X-Google-Smtp-Source: AGHT+IHZ71ikH5GOGKK2FBKAvdfHBa6SZzZeO/rqCoSoZ/izzsbiqHX1eLx5BjhVYXCTIdyY6Ms3RA==
X-Received: by 2002:a05:622a:418c:b0:4b3:4f38:5993 with SMTP id d75a77b69052e-4b34f385dd5mr16886281cf.28.1756824574335;
        Tue, 02 Sep 2025 07:49:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcgqN3qU2tzZwk0IEknAlBnFLhT3OsuwBI9BU+b6srqVg==
Received: by 2002:a05:622a:4c6:b0:4b2:e402:2d48 with SMTP id
 d75a77b69052e-4b2fe3e81f8ls47338901cf.0.-pod-prod-00-us-canary; Tue, 02 Sep
 2025 07:49:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDaDM95eJTHS5+P3WFOuH/oZnNjYYkiEUdxXLvjOE+0FLEc+Y/IikMKqjb11NHd2EZ2V8J4WNHJ8Q=@googlegroups.com
X-Received: by 2002:a05:620a:371a:b0:7fc:a265:9024 with SMTP id af79cd13be357-7fed7731835mr1425023385a.40.1756824572764;
        Tue, 02 Sep 2025 07:49:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824572; cv=none;
        d=google.com; s=arc-20240605;
        b=lCNQWfCYmjtQvenTL8tjvXJX03vQUR8BhWfZtbV1h5TLEq3hesJpww7JbiqrysKt6+
         rR8fsnZPyfqDMuDsFDpPQjKTBzzlVfBPk3cErLJjOk+AaBoGPiEAEAjWjPmW5haspNkM
         s9GusC9wh6jD5G2uIZu/f40XkluS7Xe8PbzXSog7EI0prE/uhG5xYFkmHfnowjnSvXlv
         AfcwyvOK28Gchi6WLfAWeDtlm5AQuHVOZoz/RLhCM0Vi5ph8pC3MF7u6J6QTzl22d5fn
         7We9/AjVogHNk08lv8m5hde/+SwV2G7+B39aaDP7X5wYB+G9z0oYmGd78/6Cx+EeVAMo
         gZpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FQapdzLEWvib4wee/iBeh13SXG3LZXCh6iREE8hdeBg=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=B2WMuYsdbj8w4Q06xwuqCxidjqYt5aYq/8TPMeIJFlRQKSs5mZKTjZYg+NNujNdFbV
         98B5sVpjnVNCQC9cT+12gv+nVq3jQulcMqv6jBNXNTgstx6MM45O+4ClwAuz/od0bcPD
         660GZEOzSk+1czZ1DMXYKQiO7+eb7W6IrWAHUJ5nocbl4GhfnpyplHj62WJFpv8Mvd0A
         izMldcxHKyLQs5JxRPmH5mVXLerAzHPBDgrQLQj1ZmD0zZ+hV/MyGfKC13dOT5ekp3NB
         CbKo5dJyAecr8Iw1gB5xd9OebuDPueFiYZ98nnOp/UFc1rgIxEE8JRzxV0N+YQrvlwuo
         FUpw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=agxG7jxN;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-806979a79e8si7699185a.2.2025.09.02.07.49.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:49:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 0C51C41994;
	Tue,  2 Sep 2025 14:49:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9A196C4CEED;
	Tue,  2 Sep 2025 14:49:30 +0000 (UTC)
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
Subject: [PATCH v5 07/16] dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
Date: Tue,  2 Sep 2025 17:48:44 +0300
Message-ID: <6b2f4cb436c98d6342db69e965a5621707b9711f.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=agxG7jxN;       spf=pass
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

Convert the DMA direct mapping functions to accept physical addresses
directly instead of page+offset parameters. The functions were already
operating on physical addresses internally, so this change eliminates
the redundant page-to-physical conversion at the API boundary.

The functions dma_direct_map_page() and dma_direct_unmap_page() are
renamed to dma_direct_map_phys() and dma_direct_unmap_phys() respectively,
with their calling convention changed from (struct page *page,
unsigned long offset) to (phys_addr_t phys).

Architecture-specific functions arch_dma_map_page_direct() and
arch_dma_unmap_page_direct() are similarly renamed to
arch_dma_map_phys_direct() and arch_dma_unmap_phys_direct().

The is_pci_p2pdma_page() checks are replaced with DMA_ATTR_MMIO checks
to allow integration with dma_direct_map_resource and dma_direct_map_phys()
is extended to support MMIO path either.

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 arch/powerpc/kernel/dma-iommu.c |  4 +--
 include/linux/dma-map-ops.h     |  8 ++---
 kernel/dma/direct.c             |  6 ++--
 kernel/dma/direct.h             | 57 +++++++++++++++++++++------------
 kernel/dma/mapping.c            |  8 ++---
 5 files changed, 49 insertions(+), 34 deletions(-)

diff --git a/arch/powerpc/kernel/dma-iommu.c b/arch/powerpc/kernel/dma-iommu.c
index 4d64a5db50f3..0359ab72cd3b 100644
--- a/arch/powerpc/kernel/dma-iommu.c
+++ b/arch/powerpc/kernel/dma-iommu.c
@@ -14,7 +14,7 @@
 #define can_map_direct(dev, addr) \
 	((dev)->bus_dma_limit >= phys_to_dma((dev), (addr)))
 
-bool arch_dma_map_page_direct(struct device *dev, phys_addr_t addr)
+bool arch_dma_map_phys_direct(struct device *dev, phys_addr_t addr)
 {
 	if (likely(!dev->bus_dma_limit))
 		return false;
@@ -24,7 +24,7 @@ bool arch_dma_map_page_direct(struct device *dev, phys_addr_t addr)
 
 #define is_direct_handle(dev, h) ((h) >= (dev)->archdata.dma_offset)
 
-bool arch_dma_unmap_page_direct(struct device *dev, dma_addr_t dma_handle)
+bool arch_dma_unmap_phys_direct(struct device *dev, dma_addr_t dma_handle)
 {
 	if (likely(!dev->bus_dma_limit))
 		return false;
diff --git a/include/linux/dma-map-ops.h b/include/linux/dma-map-ops.h
index f48e5fb88bd5..71f5b3025415 100644
--- a/include/linux/dma-map-ops.h
+++ b/include/linux/dma-map-ops.h
@@ -392,15 +392,15 @@ void *arch_dma_set_uncached(void *addr, size_t size);
 void arch_dma_clear_uncached(void *addr, size_t size);
 
 #ifdef CONFIG_ARCH_HAS_DMA_MAP_DIRECT
-bool arch_dma_map_page_direct(struct device *dev, phys_addr_t addr);
-bool arch_dma_unmap_page_direct(struct device *dev, dma_addr_t dma_handle);
+bool arch_dma_map_phys_direct(struct device *dev, phys_addr_t addr);
+bool arch_dma_unmap_phys_direct(struct device *dev, dma_addr_t dma_handle);
 bool arch_dma_map_sg_direct(struct device *dev, struct scatterlist *sg,
 		int nents);
 bool arch_dma_unmap_sg_direct(struct device *dev, struct scatterlist *sg,
 		int nents);
 #else
-#define arch_dma_map_page_direct(d, a)		(false)
-#define arch_dma_unmap_page_direct(d, a)	(false)
+#define arch_dma_map_phys_direct(d, a)		(false)
+#define arch_dma_unmap_phys_direct(d, a)	(false)
 #define arch_dma_map_sg_direct(d, s, n)		(false)
 #define arch_dma_unmap_sg_direct(d, s, n)	(false)
 #endif
diff --git a/kernel/dma/direct.c b/kernel/dma/direct.c
index 24c359d9c879..fa75e3070073 100644
--- a/kernel/dma/direct.c
+++ b/kernel/dma/direct.c
@@ -453,7 +453,7 @@ void dma_direct_unmap_sg(struct device *dev, struct scatterlist *sgl,
 		if (sg_dma_is_bus_address(sg))
 			sg_dma_unmark_bus_address(sg);
 		else
-			dma_direct_unmap_page(dev, sg->dma_address,
+			dma_direct_unmap_phys(dev, sg->dma_address,
 					      sg_dma_len(sg), dir, attrs);
 	}
 }
@@ -476,8 +476,8 @@ int dma_direct_map_sg(struct device *dev, struct scatterlist *sgl, int nents,
 			 */
 			break;
 		case PCI_P2PDMA_MAP_NONE:
-			sg->dma_address = dma_direct_map_page(dev, sg_page(sg),
-					sg->offset, sg->length, dir, attrs);
+			sg->dma_address = dma_direct_map_phys(dev, sg_phys(sg),
+					sg->length, dir, attrs);
 			if (sg->dma_address == DMA_MAPPING_ERROR) {
 				ret = -EIO;
 				goto out_unmap;
diff --git a/kernel/dma/direct.h b/kernel/dma/direct.h
index d2c0b7e632fc..3f4792910604 100644
--- a/kernel/dma/direct.h
+++ b/kernel/dma/direct.h
@@ -80,42 +80,57 @@ static inline void dma_direct_sync_single_for_cpu(struct device *dev,
 		arch_dma_mark_clean(paddr, size);
 }
 
-static inline dma_addr_t dma_direct_map_page(struct device *dev,
-		struct page *page, unsigned long offset, size_t size,
-		enum dma_data_direction dir, unsigned long attrs)
+static inline dma_addr_t dma_direct_map_phys(struct device *dev,
+		phys_addr_t phys, size_t size, enum dma_data_direction dir,
+		unsigned long attrs)
 {
-	phys_addr_t phys = page_to_phys(page) + offset;
-	dma_addr_t dma_addr = phys_to_dma(dev, phys);
+	dma_addr_t dma_addr;
 
 	if (is_swiotlb_force_bounce(dev)) {
-		if (is_pci_p2pdma_page(page))
-			return DMA_MAPPING_ERROR;
+		if (attrs & DMA_ATTR_MMIO)
+			goto err_overflow;
+
 		return swiotlb_map(dev, phys, size, dir, attrs);
 	}
 
-	if (unlikely(!dma_capable(dev, dma_addr, size, true)) ||
-	    dma_kmalloc_needs_bounce(dev, size, dir)) {
-		if (is_pci_p2pdma_page(page))
-			return DMA_MAPPING_ERROR;
-		if (is_swiotlb_active(dev))
-			return swiotlb_map(dev, phys, size, dir, attrs);
-
-		dev_WARN_ONCE(dev, 1,
-			     "DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
-			     &dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
-		return DMA_MAPPING_ERROR;
+	if (attrs & DMA_ATTR_MMIO) {
+		dma_addr = phys;
+		if (unlikely(dma_capable(dev, dma_addr, size, false)))
+			goto err_overflow;
+	} else {
+		dma_addr = phys_to_dma(dev, phys);
+		if (unlikely(!dma_capable(dev, dma_addr, size, true)) ||
+		    dma_kmalloc_needs_bounce(dev, size, dir)) {
+			if (is_swiotlb_active(dev))
+				return swiotlb_map(dev, phys, size, dir, attrs);
+
+			goto err_overflow;
+		}
 	}
 
-	if (!dev_is_dma_coherent(dev) && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
+	if (!dev_is_dma_coherent(dev) &&
+	    !(attrs & (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_MMIO)))
 		arch_sync_dma_for_device(phys, size, dir);
 	return dma_addr;
+
+err_overflow:
+	dev_WARN_ONCE(
+		dev, 1,
+		"DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
+		&dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
+	return DMA_MAPPING_ERROR;
 }
 
-static inline void dma_direct_unmap_page(struct device *dev, dma_addr_t addr,
+static inline void dma_direct_unmap_phys(struct device *dev, dma_addr_t addr,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
-	phys_addr_t phys = dma_to_phys(dev, addr);
+	phys_addr_t phys;
+
+	if (attrs & DMA_ATTR_MMIO)
+		/* nothing to do: uncached and no swiotlb */
+		return;
 
+	phys = dma_to_phys(dev, addr);
 	if (!(attrs & DMA_ATTR_SKIP_CPU_SYNC))
 		dma_direct_sync_single_for_cpu(dev, addr, size, dir);
 
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 58482536db9b..80481a873340 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -166,8 +166,8 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		return DMA_MAPPING_ERROR;
 
 	if (dma_map_direct(dev, ops) ||
-	    arch_dma_map_page_direct(dev, phys + size))
-		addr = dma_direct_map_page(dev, page, offset, size, dir, attrs);
+	    arch_dma_map_phys_direct(dev, phys + size))
+		addr = dma_direct_map_phys(dev, phys, size, dir, attrs);
 	else if (use_dma_iommu(dev))
 		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
 	else
@@ -187,8 +187,8 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 
 	BUG_ON(!valid_dma_direction(dir));
 	if (dma_map_direct(dev, ops) ||
-	    arch_dma_unmap_page_direct(dev, addr + size))
-		dma_direct_unmap_page(dev, addr, size, dir, attrs);
+	    arch_dma_unmap_phys_direct(dev, addr + size))
+		dma_direct_unmap_phys(dev, addr, size, dir, attrs);
 	else if (use_dma_iommu(dev))
 		iommu_dma_unmap_phys(dev, addr, size, dir, attrs);
 	else
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6b2f4cb436c98d6342db69e965a5621707b9711f.1756822782.git.leon%40kernel.org.
