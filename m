Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBAHNSLCQMGQEMQ5N3CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C9492B2CAD9
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:38:09 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-70a9f5bb140sf186222796d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:38:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625088; cv=pass;
        d=google.com; s=arc-20240605;
        b=L3Hjrnu8RmHIbTXBhrvUaeSI7Bp9F7RkMNuopwKIGRcFDFXznTjh9//C1sqELY+0oT
         wjiiuV8Jk1QwveML1KDgrMqEJHUi/uofEsrKrgmfmS6T9x+ovYI9GRwpyY0ZntOKhwxm
         Ll3RUmvO7aMkIEVsEuxl+qpLAK3Ib8aSL2f1nGKz1dj2l5hHLK8zSyXt9t5DzJyBFC8b
         OXD1Ne6TSox0P2DR/aETE7s1T6wi+XRog4Q899d/Qk3sVA6dWyPgQOCftlo/2Zb06NZL
         ddN2df6K5PEDkGwt93cMKXSdyCVsJg7PJS7wmgnTzAcF9b0wMp2Pbg6Pxh1yHYMQQT/H
         4QdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=DupbdfNqKtCuI6OuFd2RnmX4UZIKNUusAKRnsBptyG8=;
        fh=fEItdyo6aqd9P0UYw3esaL/bId6FmUWu/L5QfE9wldM=;
        b=GPL1GIM2wVIrikxV7NGB5smSPYJbrmSOPYAiueePxq7uFasRJOUJvjymT7OoZ0iZuN
         7k8sDvx8pgN5ZeWLaKxVe2mSAWKgGPpfJC5Fk4oMN8e1j69v7doGMgNP5cphcwbWW/Yi
         MeCkbmooSUUmWxwxHJj+mJfC4sVbDBQ2NvrLr2dwVjKal7OrdlHjn2OQnjN3BScO+8xD
         MCRFXFDPAWZgUThyuyHHFd+lNNWY0jmDcS+OsdxmzKCLuRKa5KlQb2z2FZmXpNT3/78J
         eOWjGmTZsMcvgq9S9mlpmJMMcQiaVffok8XIAAuVl8LB9LqVUBgFGmbNVkU24VbCgMJX
         j2IQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="rckaxg/q";
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625088; x=1756229888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DupbdfNqKtCuI6OuFd2RnmX4UZIKNUusAKRnsBptyG8=;
        b=JK4kANVtNeZTDj/iDqZW/SPY0D6AvC9yq4zHxDklINXQnJv7K1mdU4z99e77KP5VUv
         2FRVU1G2sYPEXrOzq0KXlZSgjWTSEG9cjxVkT39n/AKr88tBHNC1fyhOMVSFFDEFH4CB
         E2O079EFAeOpHwCDDl5R0vetdL1rPaqHzAtHcI+SaKKDgEG5oHHToGnrVx8ZJar5YkET
         7DuEO95Flu+1qe+n6iSzEPc61ZbsacL2NQRdSAJk9+qEXvTQLsEwrcaUtblwFS7tJl2P
         BssoLhGH5MUuOzZsJSuqoCuTTmYx7/32O862CjHpNGPumHjPA1uopzhBlZMjNM92EoRq
         D7Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625088; x=1756229888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DupbdfNqKtCuI6OuFd2RnmX4UZIKNUusAKRnsBptyG8=;
        b=EinKULB2HELfeXcipCmg0FwzF6xGi2clYAhhCybX5nnHRrnvR3rbYmC3JKnWYqanIf
         ft+3hTGYdmDxsr9QZbrV8/knlSc9Co+SE352TvO3xhT6B3wEvLrR4tNAUJ9MSuZCA9CM
         R6k/0vRgNKVPC+2/yRtn/X6slAmSwbqhLJhmnYIOeqC73WymPHxNdjxdTdgkxdE7UejI
         Bk9Pi7ZZ/vOOYjs0TtYZLlEIHdmTcpcbZz2tXF8BUMy0QCXefUAj6D/oiJzws0kGGwTf
         JizZovXBwWa+narQK5OrWURcUK4voFboWVCJWBp9DozwgozadLozDEm+bGsVo3O3OjwX
         7DtA==
X-Forwarded-Encrypted: i=2; AJvYcCXZJYTPnF7WGtul6mxrHAaveOBSlUFM1ylKEvyGwSmmRiCykqLAatAPxemKFUB+cfDEvHIUwA==@lfdr.de
X-Gm-Message-State: AOJu0YzwOAQbrdL+oQW0LUvY3FzaT3LryBbwKBvqmLTXwo6pE0t5lRNm
	z+B9aT8da/e42DsNMLwsfDLlng3/xkZrA89PTyxEux/zNPeF0YfM4S75
X-Google-Smtp-Source: AGHT+IHK5OWv7YKDHCCU9Cjhlqer9zE2Xy/G5aWaK4rjx+BaeQlZerkb9vkcakcbaYQl9f+2RMTu/A==
X-Received: by 2002:a05:6214:54c4:b0:70d:6df4:1b14 with SMTP id 6a1803df08f44-70d6df41d87mr22579516d6.66.1755625088330;
        Tue, 19 Aug 2025 10:38:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZentZ8rp3ObY9+JVtd/4eXX8HFNImC5OOQVDi7Eb3Gm9Q==
Received: by 2002:a05:6214:27c6:b0:707:4680:6fef with SMTP id
 6a1803df08f44-70ab7a1a0d1ls71280126d6.1.-pod-prod-06-us; Tue, 19 Aug 2025
 10:38:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8UF5YDerjPMJK8XtdJ9xihI0nwv6I97yd5f+2cG+0lY8bTpschr900YLuCdNqQ7UdDNHX4txm5M8=@googlegroups.com
X-Received: by 2002:a05:6122:1ad4:b0:53c:6d68:1ccb with SMTP id 71dfb90a1353d-53c6d686b6emr84254e0c.13.1755625086558;
        Tue, 19 Aug 2025 10:38:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625086; cv=none;
        d=google.com; s=arc-20240605;
        b=Qr3D1xsxxBsCWtdf4xE6dgBKMdfwP37TiHj48MwViLUnLQpI8yuXCi3fCYuQRssgDC
         AEcpwK+JvzQdBJSRbgJRMsNjnthQe3V12HssIzOX0VyllMoCVoWn7Rk2jU9LkWfrjJ+E
         Ryvwl567ysOYRH5A9cew2gvlnpouQPHIUhObsBggqqNmDI37AJvj+AXs442NaHL6U6Q9
         tMrO4HkfjplOcApZ78jYqj3bdjXsts679zYv5vNDcBLuPbT6S194kVK5Aci+FjDfN8Cx
         twLRLuy5i8jjXgzIog/MeTFe81D0UEq06OHO2SeZicXN8MiJXlRvBcn5eQm0ae7IqKRq
         TFLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jrbvw9rOWoWngXahJIZ+jx/PMyl/cB74JnS12q9ePqA=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=LA1DEOZWzsYr/r4Nbl+C083QpGd17OfHrqvX3FaLPQGwWoGEyYG2yORQYRrcwBtSd3
         8mNs0GdclkbHquZ9EXcsX38Ph9j8FRrTt7xYczQEG3im7tVB71/CSguHL79CQXkLgB5C
         sfANqlx39wQkDx+9mFOqOwZcFVd9nOjRtKBegbYgERKR7DhltGV/FuX0pcXpT5A4H8YL
         BT1DVphoeYdy/NA+SYvrqnKMNGTOjtlebylCBfUodPf4z2Zp/BFnZQrcDqnVOKJQBnZd
         zWAvmrIgtdx4IKg35DjEKQ/JgA+8LPIdBVSkdKRg2q5M4FyfUSEqGveSFSE0+tBSy3WT
         rVvA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="rckaxg/q";
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53b2be4f45asi469106e0c.2.2025.08.19.10.38.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:38:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id CB1DE61427;
	Tue, 19 Aug 2025 17:38:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 763E9C4CEF4;
	Tue, 19 Aug 2025 17:38:04 +0000 (UTC)
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
Subject: [PATCH v4 07/16] dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
Date: Tue, 19 Aug 2025 20:36:51 +0300
Message-ID: <3faa9c978e243a904ffe01496148c4563dc9274e.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="rckaxg/q";       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
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

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 arch/powerpc/kernel/dma-iommu.c |  4 +--
 include/linux/dma-map-ops.h     |  8 ++---
 kernel/dma/direct.c             |  6 ++--
 kernel/dma/direct.h             | 52 +++++++++++++++++++++------------
 kernel/dma/mapping.c            |  8 ++---
 5 files changed, 46 insertions(+), 32 deletions(-)

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
index d2c0b7e632fc..92dbadcd3b2f 100644
--- a/kernel/dma/direct.h
+++ b/kernel/dma/direct.h
@@ -80,42 +80,56 @@ static inline void dma_direct_sync_single_for_cpu(struct device *dev,
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
+	bool capable;
 
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
+	if (attrs & DMA_ATTR_MMIO)
+		dma_addr = phys;
+	else
+		dma_addr = phys_to_dma(dev, phys);
+
+	capable = dma_capable(dev, dma_addr, size, !(attrs & DMA_ATTR_MMIO));
+	if (unlikely(!capable) || dma_kmalloc_needs_bounce(dev, size, dir)) {
+		if (is_swiotlb_active(dev) && !(attrs & DMA_ATTR_MMIO))
 			return swiotlb_map(dev, phys, size, dir, attrs);
 
-		dev_WARN_ONCE(dev, 1,
-			     "DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
-			     &dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
-		return DMA_MAPPING_ERROR;
+		goto err_overflow;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3faa9c978e243a904ffe01496148c4563dc9274e.1755624249.git.leon%40kernel.org.
