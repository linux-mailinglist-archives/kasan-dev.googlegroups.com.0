Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB4OF7DCAMGQEHPWKLOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 624C6B26E16
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:55:17 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-32326bd7502sf1167426a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:55:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194097; cv=pass;
        d=google.com; s=arc-20240605;
        b=O1JhEkcb3Ea9IQi7Ea7R+mjPwr8g+9Bb36oWRf/Kni9YZsrKisAAHsyKHwQxn3F99K
         XziBbTfcsB9SxZGdquGMXF5PVoS0LCPKa9Y0EoemrZY+xQPL6a8z75t7osKC0F6dDuVY
         olLGg2HiGBnMSGs8uOxflk22wVvp2tV4+hVWKVDmcItGzhOlPP6HRUNWJRQC81E2HuPO
         bj3IoyYWSq4ym2uYMHeHrcr5ZXYZZPGYXlG4udWpjR9OKXQmx90G6eMMmwPGc01Lg8LC
         D+av5+sW9JPy4jrpNmtdNcYfavSpKdjjrhAEjBa7n6cR8C/Fj9BzNP5NS02OPrpGhdP6
         D+tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=aS8ZSJPJoFHhngOEwFhyTVszjQBc71PXfO/DeLvfQEo=;
        fh=1b99CIAHYpA8yQLpvbjYPa2WqD+fEVD8ROAvZYaE5Ls=;
        b=OklRS+QG/ICPlLr+x5mwwKlEwJpaJQ6dc9tVZ9FaiI0Kq4Qo0GeMg97M3DR8yH2SS9
         Ycq8cXLiKX6Ko3wAIC3sBtoK9s+sPrMUHGw1ULwPv6trXo9YQRbQplQlsPuofOTxSGE9
         7zdmlRgtx2SdEI/kZzcbHFOmrrHwp6P5qIKV1Sn4qH0ZejE1tU4gCj2yj9X60aPs0VY/
         /sTGFHHtejCyg1TTozq4wSE4MbVguul64k9xM7G0oGobhLxY4insiIQQiMiourPDXPPk
         aKcKZ1zgKk+SVgRf8Fy2a/esPBHq0KYwl9+B9kzx8O1RpehYTYQ+ttqeTpzWzYYsc8fD
         U8Ug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bHYYYSKA;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194097; x=1755798897; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=aS8ZSJPJoFHhngOEwFhyTVszjQBc71PXfO/DeLvfQEo=;
        b=FeXF/O/wpTHRx6l1jDOd08PT4NXsMZFiZ+HTDqZzS0H8ewt+QDkgB9cqi1socSzQ81
         5zP2HAID7++6pQAAlOsKVKSPvdQSmLd+JnwbfwK3dV44cYpZyqh4JdWExeB3aCqiod07
         xRqPYi8kBWyGgWCNaVnFIWrkTvoXZKyAk9xdd2X9WaGlTW1KD31zVyMCoSUswxjgDgse
         0lPgYMaoQXJht0nRcjkHAOrPU4PUyi4158KWsCm482ToEWj1Or5iZ+BMguEq9blen6r4
         0RhP/k3YKHuuL8GJSmpHugS9kQ9A5+dcU+5lQFQ0z2wBIw4y6Ba0FEUwx9x5+bxgTtHf
         b+Pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194097; x=1755798897;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aS8ZSJPJoFHhngOEwFhyTVszjQBc71PXfO/DeLvfQEo=;
        b=PijaLL40ggUxeZ22eUw63mNbb74UW+NPTjLU0NVfXG7ahH0qJVzdKTEIXhmMTId4gn
         Pxcv1Ib1fPLqRmPIKikATTHqa+u2AoDEHmn9iHOZW3LJIvogjD9mq5WIgdUaF0VhaVQV
         H3YBwf/W43YdZ4HfvyT2+NRycR1Je9Rt9mB6s+UClSfbcWwXFY7odBYEH8pSg+k60MDh
         1Iy3LZCfH1y2NKClCpqS7arSu02KkgV0DrttqL+/y61RsiNCCw0q0wq4DKjNIVK7s/XF
         2WrSJrIxBs0qk81rTaYimRAhzgOhyWcuzRF4PAjMFpqpTiLCoJ8UPJm/pKsKF9zjvR89
         0q0Q==
X-Forwarded-Encrypted: i=2; AJvYcCUDeL6imLNJc6H9NRSruYHwsJDJZozfEyLPlvJgpp3QpfjKghbvobRlIIZVtK9nSsuXfembbA==@lfdr.de
X-Gm-Message-State: AOJu0YxjEt1ipzR+Ht2L50mfFzM/O6fBVzgJAWCh9NbhMvGp5SYaLntV
	uWlI4Q5zmzn6kFGxfeaYJ1gPJzw5jvkm3UD0Rvk0TgLVEIjrQd6vkAiZ
X-Google-Smtp-Source: AGHT+IFqw4OHFuOsujb2MWy8riMhTlMEqEDzekMGg1HXpqC5NXwDDxMx++OU4NszlDD72KBDtVJtlw==
X-Received: by 2002:a17:90b:3dc3:b0:321:59e7:c5ba with SMTP id 98e67ed59e1d1-32327ae0b01mr6512857a91.15.1755194097425;
        Thu, 14 Aug 2025 10:54:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcjFp6FYxtVFHJgZ47n5s1BopWfXJykaT5XDnalqhh5Pw==
Received: by 2002:a17:90b:2689:b0:321:6ddc:3398 with SMTP id
 98e67ed59e1d1-32326df5f89ls1203861a91.2.-pod-prod-05-us; Thu, 14 Aug 2025
 10:54:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVudT6BG2WTPdg0clZ/XjL35GrY+6CRsivtgm2ylYQbKjDZhJ4rjw12fEmg4qdlkOrB4ibKZZ8lLUw=@googlegroups.com
X-Received: by 2002:a17:90b:35d0:b0:321:27d5:eaf1 with SMTP id 98e67ed59e1d1-32327b48f77mr5969020a91.25.1755194095341;
        Thu, 14 Aug 2025 10:54:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194095; cv=none;
        d=google.com; s=arc-20240605;
        b=DvhPDQmMys85nauOBWRoXHmhoJDfuYfbs6dH88eKs+irxkXGF2fYwh2G2rZ+DOZHas
         q/BtZRE10mfKAEZv2TtUiVvn4nAAv61nxup+1pdlL974uCBujFGbetpszY2nFlWA2G1Q
         4wqyHO8IylGBS9O4Cn8DotERzceIBBABl9P9TJrALTiDZBwyGtEc9DrSIYq1eq2DUw6f
         AG0BFBRWrDfZWni5kLYBeQ0KAAVhfrjmAFFK8/ZebT5VAn89pAuqUjmvGKkkjwDvSMj0
         bViVuNLC1M2wDx06eLUMQD4G1KCMa0aPH2ns67cTTvIVDIPCxTNfUt+QcgwMJH7nEGDx
         cfhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6wpDDK6cIOpZvCaJNMQsaJEJNnsJ8lmKgCJXsKe4wl4=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=RuTqZwaF4caSZI1S1xlzbfZGcbezJIQxoowzTP6b/yoNeoQSX6yUVoD4UI8QJBhB2P
         CscK6jsUYS/c8xgxdxrJJxxhXZU9vqUDarxcIjPVHMe75a7cGi96e8rcY87W17Aik2Cg
         8QT6YeMSaoVDQhprAib8q7W9FeyMOP6lWBMBgKSGmouxQBAe45uwyUeHuOOL1whtUiML
         J6AWne4OfMrVE1EfYXUy4wl3O9XLPW7IqD+3nvBhbgGuzMNAqVSI8TAtLDHEaoIKHadi
         3E8FK6EsUZZ+IWPDv0HFv41fT9XC/kg90qPTTIaxoo2nMNOu5bwblgvvM4+Ostu7A0EE
         yzDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bHYYYSKA;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32329a63f35si122672a91.1.2025.08.14.10.54.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:54:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id EBD5043F94;
	Thu, 14 Aug 2025 17:54:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2419DC4CEED;
	Thu, 14 Aug 2025 17:54:54 +0000 (UTC)
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
Subject: [PATCH v3 11/16] dma-mapping: export new dma_*map_phys() interface
Date: Thu, 14 Aug 2025 20:54:02 +0300
Message-ID: <60724b0fdc808c8290014ae38a2ee5d9f3d091ee.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bHYYYSKA;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted
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

Introduce new DMA mapping functions dma_map_phys() and dma_unmap_phys()
that operate directly on physical addresses instead of page+offset
parameters. This provides a more efficient interface for drivers that
already have physical addresses available.

The new functions are implemented as the primary mapping layer, with
the existing dma_map_page_attrs()/dma_map_resource() and
dma_unmap_page_attrs()/dma_unmap_resource() functions converted to simple
wrappers around the phys-based implementations.

In case dma_map_page_attrs(), the struct page is converted to physical
address with help of page_to_phys() function and dma_map_resource()
provides physical address as is together with addition of DMA_ATTR_MMIO
attribute.

The old page-based API is preserved in mapping.c to ensure that existing
code won't be affected by changing EXPORT_SYMBOL to EXPORT_SYMBOL_GPL
variant for dma_*map_phys().

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c   | 14 --------
 include/linux/dma-direct.h  |  2 --
 include/linux/dma-mapping.h | 13 +++++++
 include/linux/iommu-dma.h   |  4 ---
 include/trace/events/dma.h  |  2 --
 kernel/dma/debug.c          | 43 -----------------------
 kernel/dma/debug.h          | 21 -----------
 kernel/dma/direct.c         | 16 ---------
 kernel/dma/mapping.c        | 69 ++++++++++++++++++++-----------------
 9 files changed, 50 insertions(+), 134 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index 6804aaf034a1..7944a3af4545 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1556,20 +1556,6 @@ void iommu_dma_unmap_sg(struct device *dev, struct scatterlist *sg, int nents,
 		__iommu_dma_unmap(dev, start, end - start);
 }
 
-dma_addr_t iommu_dma_map_resource(struct device *dev, phys_addr_t phys,
-		size_t size, enum dma_data_direction dir, unsigned long attrs)
-{
-	return __iommu_dma_map(dev, phys, size,
-			dma_info_to_prot(dir, false, attrs) | IOMMU_MMIO,
-			dma_get_mask(dev));
-}
-
-void iommu_dma_unmap_resource(struct device *dev, dma_addr_t handle,
-		size_t size, enum dma_data_direction dir, unsigned long attrs)
-{
-	__iommu_dma_unmap(dev, handle, size);
-}
-
 static void __iommu_dma_free(struct device *dev, size_t size, void *cpu_addr)
 {
 	size_t alloc_size = PAGE_ALIGN(size);
diff --git a/include/linux/dma-direct.h b/include/linux/dma-direct.h
index f3bc0bcd7098..c249912456f9 100644
--- a/include/linux/dma-direct.h
+++ b/include/linux/dma-direct.h
@@ -149,7 +149,5 @@ void dma_direct_free_pages(struct device *dev, size_t size,
 		struct page *page, dma_addr_t dma_addr,
 		enum dma_data_direction dir);
 int dma_direct_supported(struct device *dev, u64 mask);
-dma_addr_t dma_direct_map_resource(struct device *dev, phys_addr_t paddr,
-		size_t size, enum dma_data_direction dir, unsigned long attrs);
 
 #endif /* _LINUX_DMA_DIRECT_H */
diff --git a/include/linux/dma-mapping.h b/include/linux/dma-mapping.h
index 4254fd9bdf5d..8248ff9363ee 100644
--- a/include/linux/dma-mapping.h
+++ b/include/linux/dma-mapping.h
@@ -138,6 +138,10 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		unsigned long attrs);
 void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 		enum dma_data_direction dir, unsigned long attrs);
+dma_addr_t dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		enum dma_data_direction dir, unsigned long attrs);
+void dma_unmap_phys(struct device *dev, dma_addr_t addr, size_t size,
+		enum dma_data_direction dir, unsigned long attrs);
 unsigned int dma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
 		int nents, enum dma_data_direction dir, unsigned long attrs);
 void dma_unmap_sg_attrs(struct device *dev, struct scatterlist *sg,
@@ -192,6 +196,15 @@ static inline void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
 }
+static inline dma_addr_t dma_map_phys(struct device *dev, phys_addr_t phys,
+		size_t size, enum dma_data_direction dir, unsigned long attrs)
+{
+	return DMA_MAPPING_ERROR;
+}
+static inline void dma_unmap_phys(struct device *dev, dma_addr_t addr,
+		size_t size, enum dma_data_direction dir, unsigned long attrs)
+{
+}
 static inline unsigned int dma_map_sg_attrs(struct device *dev,
 		struct scatterlist *sg, int nents, enum dma_data_direction dir,
 		unsigned long attrs)
diff --git a/include/linux/iommu-dma.h b/include/linux/iommu-dma.h
index 485bdffed988..a92b3ff9b934 100644
--- a/include/linux/iommu-dma.h
+++ b/include/linux/iommu-dma.h
@@ -42,10 +42,6 @@ size_t iommu_dma_opt_mapping_size(void);
 size_t iommu_dma_max_mapping_size(struct device *dev);
 void iommu_dma_free(struct device *dev, size_t size, void *cpu_addr,
 		dma_addr_t handle, unsigned long attrs);
-dma_addr_t iommu_dma_map_resource(struct device *dev, phys_addr_t phys,
-		size_t size, enum dma_data_direction dir, unsigned long attrs);
-void iommu_dma_unmap_resource(struct device *dev, dma_addr_t handle,
-		size_t size, enum dma_data_direction dir, unsigned long attrs);
 struct sg_table *iommu_dma_alloc_noncontiguous(struct device *dev, size_t size,
 		enum dma_data_direction dir, gfp_t gfp, unsigned long attrs);
 void iommu_dma_free_noncontiguous(struct device *dev, size_t size,
diff --git a/include/trace/events/dma.h b/include/trace/events/dma.h
index 84416c7d6bfa..5da59fd8121d 100644
--- a/include/trace/events/dma.h
+++ b/include/trace/events/dma.h
@@ -73,7 +73,6 @@ DEFINE_EVENT(dma_map, name, \
 	TP_ARGS(dev, phys_addr, dma_addr, size, dir, attrs))
 
 DEFINE_MAP_EVENT(dma_map_phys);
-DEFINE_MAP_EVENT(dma_map_resource);
 
 DECLARE_EVENT_CLASS(dma_unmap,
 	TP_PROTO(struct device *dev, dma_addr_t addr, size_t size,
@@ -111,7 +110,6 @@ DEFINE_EVENT(dma_unmap, name, \
 	TP_ARGS(dev, addr, size, dir, attrs))
 
 DEFINE_UNMAP_EVENT(dma_unmap_phys);
-DEFINE_UNMAP_EVENT(dma_unmap_resource);
 
 DECLARE_EVENT_CLASS(dma_alloc_class,
 	TP_PROTO(struct device *dev, void *virt_addr, dma_addr_t dma_addr,
diff --git a/kernel/dma/debug.c b/kernel/dma/debug.c
index da6734e3a4ce..06e31fd216e3 100644
--- a/kernel/dma/debug.c
+++ b/kernel/dma/debug.c
@@ -38,7 +38,6 @@ enum {
 	dma_debug_single,
 	dma_debug_sg,
 	dma_debug_coherent,
-	dma_debug_resource,
 	dma_debug_phy,
 };
 
@@ -141,7 +140,6 @@ static const char *type2name[] = {
 	[dma_debug_single] = "single",
 	[dma_debug_sg] = "scatter-gather",
 	[dma_debug_coherent] = "coherent",
-	[dma_debug_resource] = "resource",
 	[dma_debug_phy] = "phy",
 };
 
@@ -1448,47 +1446,6 @@ void debug_dma_free_coherent(struct device *dev, size_t size,
 	check_unmap(&ref);
 }
 
-void debug_dma_map_resource(struct device *dev, phys_addr_t addr, size_t size,
-			    int direction, dma_addr_t dma_addr,
-			    unsigned long attrs)
-{
-	struct dma_debug_entry *entry;
-
-	if (unlikely(dma_debug_disabled()))
-		return;
-
-	entry = dma_entry_alloc();
-	if (!entry)
-		return;
-
-	entry->type		= dma_debug_resource;
-	entry->dev		= dev;
-	entry->paddr		= addr;
-	entry->size		= size;
-	entry->dev_addr		= dma_addr;
-	entry->direction	= direction;
-	entry->map_err_type	= MAP_ERR_NOT_CHECKED;
-
-	add_dma_entry(entry, attrs);
-}
-
-void debug_dma_unmap_resource(struct device *dev, dma_addr_t dma_addr,
-			      size_t size, int direction)
-{
-	struct dma_debug_entry ref = {
-		.type           = dma_debug_resource,
-		.dev            = dev,
-		.dev_addr       = dma_addr,
-		.size           = size,
-		.direction      = direction,
-	};
-
-	if (unlikely(dma_debug_disabled()))
-		return;
-
-	check_unmap(&ref);
-}
-
 void debug_dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle,
 				   size_t size, int direction)
 {
diff --git a/kernel/dma/debug.h b/kernel/dma/debug.h
index 76adb42bffd5..424b8f912ade 100644
--- a/kernel/dma/debug.h
+++ b/kernel/dma/debug.h
@@ -30,14 +30,6 @@ extern void debug_dma_alloc_coherent(struct device *dev, size_t size,
 extern void debug_dma_free_coherent(struct device *dev, size_t size,
 				    void *virt, dma_addr_t addr);
 
-extern void debug_dma_map_resource(struct device *dev, phys_addr_t addr,
-				   size_t size, int direction,
-				   dma_addr_t dma_addr,
-				   unsigned long attrs);
-
-extern void debug_dma_unmap_resource(struct device *dev, dma_addr_t dma_addr,
-				     size_t size, int direction);
-
 extern void debug_dma_sync_single_for_cpu(struct device *dev,
 					  dma_addr_t dma_handle, size_t size,
 					  int direction);
@@ -88,19 +80,6 @@ static inline void debug_dma_free_coherent(struct device *dev, size_t size,
 {
 }
 
-static inline void debug_dma_map_resource(struct device *dev, phys_addr_t addr,
-					  size_t size, int direction,
-					  dma_addr_t dma_addr,
-					  unsigned long attrs)
-{
-}
-
-static inline void debug_dma_unmap_resource(struct device *dev,
-					    dma_addr_t dma_addr, size_t size,
-					    int direction)
-{
-}
-
 static inline void debug_dma_sync_single_for_cpu(struct device *dev,
 						 dma_addr_t dma_handle,
 						 size_t size, int direction)
diff --git a/kernel/dma/direct.c b/kernel/dma/direct.c
index fa75e3070073..1062caac47e7 100644
--- a/kernel/dma/direct.c
+++ b/kernel/dma/direct.c
@@ -502,22 +502,6 @@ int dma_direct_map_sg(struct device *dev, struct scatterlist *sgl, int nents,
 	return ret;
 }
 
-dma_addr_t dma_direct_map_resource(struct device *dev, phys_addr_t paddr,
-		size_t size, enum dma_data_direction dir, unsigned long attrs)
-{
-	dma_addr_t dma_addr = paddr;
-
-	if (unlikely(!dma_capable(dev, dma_addr, size, false))) {
-		dev_err_once(dev,
-			     "DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
-			     &dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
-		WARN_ON_ONCE(1);
-		return DMA_MAPPING_ERROR;
-	}
-
-	return dma_addr;
-}
-
 int dma_direct_get_sgtable(struct device *dev, struct sg_table *sgt,
 		void *cpu_addr, dma_addr_t dma_addr, size_t size,
 		unsigned long attrs)
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index fdabfdaeff1d..0ca098d2e88d 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -152,12 +152,10 @@ static inline bool dma_map_direct(struct device *dev,
 	return dma_go_direct(dev, *dev->dma_mask, ops);
 }
 
-dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
-		size_t offset, size_t size, enum dma_data_direction dir,
-		unsigned long attrs)
+dma_addr_t dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		enum dma_data_direction dir, unsigned long attrs)
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
-	phys_addr_t phys = page_to_phys(page) + offset;
 	bool is_mmio = attrs & DMA_ATTR_MMIO;
 	dma_addr_t addr;
 
@@ -177,6 +175,9 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 
 		addr = ops->map_resource(dev, phys, size, dir, attrs);
 	} else {
+		struct page *page = phys_to_page(phys);
+		size_t offset = offset_in_page(phys);
+
 		/*
 		 * The dma_ops API contract for ops->map_page() requires
 		 * kmappable memory, while ops->map_resource() does not.
@@ -191,9 +192,26 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 
 	return addr;
 }
+EXPORT_SYMBOL_GPL(dma_map_phys);
+
+dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
+		size_t offset, size_t size, enum dma_data_direction dir,
+		unsigned long attrs)
+{
+	phys_addr_t phys = page_to_phys(page) + offset;
+
+	if (unlikely(attrs & DMA_ATTR_MMIO))
+		return DMA_MAPPING_ERROR;
+
+	if (IS_ENABLED(CONFIG_DMA_API_DEBUG) &&
+	    WARN_ON_ONCE(is_zone_device_page(page)))
+		return DMA_MAPPING_ERROR;
+
+	return dma_map_phys(dev, phys, size, dir, attrs);
+}
 EXPORT_SYMBOL(dma_map_page_attrs);
 
-void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
+void dma_unmap_phys(struct device *dev, dma_addr_t addr, size_t size,
 		enum dma_data_direction dir, unsigned long attrs)
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
@@ -213,6 +231,16 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 	trace_dma_unmap_phys(dev, addr, size, dir, attrs);
 	debug_dma_unmap_phys(dev, addr, size, dir);
 }
+EXPORT_SYMBOL_GPL(dma_unmap_phys);
+
+void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
+		 enum dma_data_direction dir, unsigned long attrs)
+{
+	if (unlikely(attrs & DMA_ATTR_MMIO))
+		return;
+
+	dma_unmap_phys(dev, addr, size, dir, attrs);
+}
 EXPORT_SYMBOL(dma_unmap_page_attrs);
 
 static int __dma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
@@ -338,41 +366,18 @@ EXPORT_SYMBOL(dma_unmap_sg_attrs);
 dma_addr_t dma_map_resource(struct device *dev, phys_addr_t phys_addr,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
-	const struct dma_map_ops *ops = get_dma_ops(dev);
-	dma_addr_t addr = DMA_MAPPING_ERROR;
-
-	BUG_ON(!valid_dma_direction(dir));
-
-	if (WARN_ON_ONCE(!dev->dma_mask))
+	if (IS_ENABLED(CONFIG_DMA_API_DEBUG) &&
+	    WARN_ON_ONCE(pfn_valid(PHYS_PFN(phys_addr))))
 		return DMA_MAPPING_ERROR;
 
-	if (dma_map_direct(dev, ops))
-		addr = dma_direct_map_resource(dev, phys_addr, size, dir, attrs);
-	else if (use_dma_iommu(dev))
-		addr = iommu_dma_map_resource(dev, phys_addr, size, dir, attrs);
-	else if (ops->map_resource)
-		addr = ops->map_resource(dev, phys_addr, size, dir, attrs);
-
-	trace_dma_map_resource(dev, phys_addr, addr, size, dir, attrs);
-	debug_dma_map_resource(dev, phys_addr, size, dir, addr, attrs);
-	return addr;
+	return dma_map_phys(dev, phys_addr, size, dir, attrs | DMA_ATTR_MMIO);
 }
 EXPORT_SYMBOL(dma_map_resource);
 
 void dma_unmap_resource(struct device *dev, dma_addr_t addr, size_t size,
 		enum dma_data_direction dir, unsigned long attrs)
 {
-	const struct dma_map_ops *ops = get_dma_ops(dev);
-
-	BUG_ON(!valid_dma_direction(dir));
-	if (dma_map_direct(dev, ops))
-		; /* nothing to do: uncached and no swiotlb */
-	else if (use_dma_iommu(dev))
-		iommu_dma_unmap_resource(dev, addr, size, dir, attrs);
-	else if (ops->unmap_resource)
-		ops->unmap_resource(dev, addr, size, dir, attrs);
-	trace_dma_unmap_resource(dev, addr, size, dir, attrs);
-	debug_dma_unmap_resource(dev, addr, size, dir);
+	dma_unmap_phys(dev, addr, size, dir, attrs | DMA_ATTR_MMIO);
 }
 EXPORT_SYMBOL(dma_unmap_resource);
 
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/60724b0fdc808c8290014ae38a2ee5d9f3d091ee.1755193625.git.leon%40kernel.org.
