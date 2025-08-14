Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBYOF7DCAMGQEIZKDD4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 48CB1B26E0D
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:54:43 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-61bd404edb3sf1057463eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:54:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194082; cv=pass;
        d=google.com; s=arc-20240605;
        b=O3EtaxLJg4iSY6BpUuBa6SgMdPp6LRffFdrqO3jtzRzxSuQEfDbEKY3A9SWAwJdpDV
         8BW5z7D+2HUTUoDD8RRds9FTGIZ39cg8TmVtHZMqtCDwu0Cf21mw1uiGCHl1tU/wdoqc
         h6VcBa2d3i7RvfEZZ8nK8Zr4WhPruVY0GyV/ZhfMktSa2nXg3MacgQPImZuD31w6GQ1n
         EH3vB82JwaOt9IxwjTUkIh4jAJwKi8wSuCBjFidRhHpDFiqQmTsWvwH6bzJpgoXiGZpe
         0VXPqxWIqG2QVqTeMnug/Phw+u7o9XM2d0TpEybiWE9vbkvgG6gQrTeIv2BZb0BOAj7v
         NBtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=HUrX3FuRM0mC2uTkFZFJnhsPvpu1pJD0ZRl8HGIZYBw=;
        fh=+mTZErRpPpZ7UlQ6ZOEUsBem7QMrQFeHpIE//pSTSEk=;
        b=N6RLLVSQ6csQsMyDRlD7hNXHGMRYzQo0c5ygL9zTaqNEf7Wzgf9/td2xhCEctEGTbe
         f2cprPMvJ77FNW84Y3UvYlQFPEuu8viJ6+JXiQGDLmGKvcWcqlYbgQW5HCWqXABtJJGe
         OA0ycgpAbNkmw3khtKSa4s/UYsc7LOVXex6Ap1o95Pqp8nCM3cjN5P3l4cgQfOhVkZsM
         eP2hdTPATiMLsrFbnWqvsi2l0quhJc6zCd2LWqeuNrw4fdzAOBV6Mc8MSp/SFMO0Ma9o
         gz4kSg7X2qCSRyA1dcTjZMW/avt9e96sLLD7Gyt4NBuDIGV/BK0RDiwOYWYB1eFERLHn
         t7gQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u8LGJqu+;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194082; x=1755798882; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=HUrX3FuRM0mC2uTkFZFJnhsPvpu1pJD0ZRl8HGIZYBw=;
        b=qnowp1xK7t1usYX55lAj0xI5JdO/w5cxwFkEhixtF+fBeYtqs+tG7etOXcivNQ4rXm
         P/3SE09O9vXMHuFkxXevUR0wYoBkvN05XLDllG1TBeoHapecC5LPKV6mS17Tzyyte8rZ
         QDKISyOKhHt8iPDm5WupbCjOd3l7U+jyL6rZ55p7+D9W7Sssc+axxGO0LJnyFznGwH/u
         S+kIYWyDQZ0TL5vl/bvpZzq0J7NACVBNEcs0WCzN0J53de3E5eL1GmSy6Gr2prc4W7BS
         4OKJk7gHTgM67u0vetOG30udo/dkBkVlR1gXvsUxEk7hRKeyoAVrleKSMb//51IIu7fk
         nnUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194082; x=1755798882;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HUrX3FuRM0mC2uTkFZFJnhsPvpu1pJD0ZRl8HGIZYBw=;
        b=OzMDD5Y9aYVH8u+g3nBEJySGOxMMSQ+9IDmxyFb//rJQaXiZOwVj27WROTQsMFfOK/
         EuU9xYMMZ32bPvueYTGag8pgUTaDmRw3OXwBTP55p49FPKom20pd8QjMAyIsmEVGPAtS
         3xlnN/p/IhGNPFMmbACMMl/pJo6NqhD3KslmF9iM1oXpmcEppGshVB/cMCxk/ktgSVka
         Mo9/wX5fQxg3wsYpFoAWyGVLNWmtW7k1vONa5xeFtN8h3MbkoqI6bAQk1JA49ESiGCK7
         Z5/i1keSCvpRvCNn2D/DPaWWr9lZi/yXn+3QxH16Fca4OzuE5q4hFMycugAHHRfZzIb3
         N07g==
X-Forwarded-Encrypted: i=2; AJvYcCXPqB8ZRGlsXhE5h5UkconEjSqANIQyDdmqsZPJr2BaM5vApAZUG82wfyqDuiljphTq3H6xRA==@lfdr.de
X-Gm-Message-State: AOJu0Yz9+NuFXbWVtKg3z0ivAoIadVcrFgqHi97SWNXA66W4tiHYF2lE
	0ANWcFYaCeB0PcVreTzE+cxbL2LW+i9ZZGPNMAmPOPgjfra6PK8PpSPM
X-Google-Smtp-Source: AGHT+IFev8K6UgUcFJnJ/dYDQZv/jKyhMP72p/3gd6MOatYXUZZEfOeXGYcVh6u5FHubWHkkZ3eJkA==
X-Received: by 2002:a05:6820:160e:b0:61b:924a:b7ab with SMTP id 006d021491bc7-61bd6e5bc37mr2150808eaf.2.1755194081771;
        Thu, 14 Aug 2025 10:54:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfezrj+FGIpZk0jHCe5s8bzDOfZqcY59xNsU68kSQS2Bw==
Received: by 2002:a05:6820:1ca6:b0:61b:3fc1:70f6 with SMTP id
 006d021491bc7-61bc5964ee5ls268073eaf.2.-pod-prod-00-us-canary; Thu, 14 Aug
 2025 10:54:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVR8SdrKFr/Q1JvQFA8PaUI9tI4WvvEmEsoHTDGiQ+N4wrw7uclXGMF51QomW1jt00SgufepRmmOxA=@googlegroups.com
X-Received: by 2002:a05:6808:1809:b0:40a:641d:677e with SMTP id 5614622812f47-435e0755563mr2159954b6e.11.1755194080547;
        Thu, 14 Aug 2025 10:54:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194080; cv=none;
        d=google.com; s=arc-20240605;
        b=fjfcGpG8Clz6FQfu/UgEZR3XNvbb6cRJipJqqjmVGwYQg+i5yLMTJKQCPXJ0xPQOnc
         r5XzBJxBxeby3YMETtykKrpiraX/tI5cYI+unka4YNJv16susP/RWDRztkW4P8aOGhQy
         PWCCZAU/4gXMq/aMqSAVEnroIWxQmMXvD9pwAHf32ZSK0aPRAtMkJoJCOnCUIeBcG8sS
         wsuc+EN/4TpvSShhfEP9wvOo6R2DD8GGgAR+aDwSVa+Oxmj/XIXrzR8msXkb/bcoTDXQ
         /GNZREgqgOkRj9HxtzXrK5du/yUdpLNXpxM/5Fkmv0/l0CDD4ZsHZF3ms/xHESO7kmyn
         xAAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jrbvw9rOWoWngXahJIZ+jx/PMyl/cB74JnS12q9ePqA=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=KPSd9JZS2MXWDy0bxb2XTjml+gLKI9LHzAZBQhncUyRHIbA5bTY2b261a3DpBN63Lw
         w5dic+sLGV3m2C4xtXdWhb/8AP86lvAkcY3tLeopDiAs+mlozv1f9LnlmN7MhBqwsI92
         qMQoO7B3TRs836ggaSmMDNc0pi3WJE2H3s+lo9zxMgn4rb/BU7vkj3eFH9TnT9vnqUYf
         O+Vfot/HKwMah6ekgKxMAUAZLDlAmyPF3yZQQyTQDYN5iuGLeZks6mCwt65/LCeqKZmh
         2dSlRiqOW3apEUNBQKLMh7TxBFjjo3UJwAuv0gxl8YJMHoK7swH6mSmyA/x8jzqHzkXi
         oo/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u8LGJqu+;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-435ce9b112fsi329471b6e.5.2025.08.14.10.54.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:54:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 3B05E5C721E;
	Thu, 14 Aug 2025 17:54:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 39032C4CEF4;
	Thu, 14 Aug 2025 17:54:39 +0000 (UTC)
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
Subject: [PATCH v3 07/16] dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
Date: Thu, 14 Aug 2025 20:53:58 +0300
Message-ID: <3faa9c978e243a904ffe01496148c4563dc9274e.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=u8LGJqu+;       spf=pass
 (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3faa9c978e243a904ffe01496148c4563dc9274e.1755193625.git.leon%40kernel.org.
