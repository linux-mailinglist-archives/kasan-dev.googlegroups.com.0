Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBAHO63CAMGQE4NDHBXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C6C5B26204
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:14:26 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-70a88de16c0sf17930426d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:14:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166465; cv=pass;
        d=google.com; s=arc-20240605;
        b=kro0kN8PEug+RyizTjGR5ytSSnFRZnBPpXYXUk8MKRSfCKIw1iVQ4rfkBewKuxHB9o
         F769grh9Z0V9/wNnPaEPNfz+47UIYJhJ81bnxcwRVql4OL3BTs74Kqxd6PmXa5bDhsKL
         X3f6/jVnXED3rCal1GffwaIGUfTF1z+Tp6qee4a340ObKWeL/qa+qSekpGXcM2V9H2fQ
         mOXNFu9S3hEU15MDIpr4iFJ3/+rmnP9Ifx4iT7L7uN3Ytbykeprq78kdJISpdY0SiMXr
         x3Qs8TdrorHN49Px3/7GPeLHcfMqO1+vW3UqPkAbTyV09rOe6hx2hC0XLSj4GCv02ta1
         AwBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=EQMs9Gxo8Fv5c51jKNoleENWxn/qtCWaIZFHF85n66U=;
        fh=GSA+/M36BQ4wta9wz6hpOq617UXNvkwrE7Lkbfx4BTk=;
        b=YjGsRnkoRUA6t7JfHiHqjNVpOZUHIWu9vP9NH93zt97Hvh4/e/9bQX1hS2cV4YWwrx
         unCskNL+UZEUnVYkHNaO6Ppb4lBLAtcSOgrmrui4AIym+aQL3zLCT4/bkeotvUKel2Ho
         8skfjlAa65Uoyz3hosgN/g9npWePB2OZqU1XEReNPsrBtcoPI1TraPcEF7U8dqXUR+TU
         BSl6Dzd5+DhunZQ20Jfr1i8CXeH+tRhg4hEJzOFuTfI/62WrMk3Ovd2ak7Fo4x4SOMEh
         Y/CCU217NEaIOBJhOzuFJG/853HhG97tiC5B37OxHpA/eLU8WvpgSow+oQWggiI/a0uE
         EJYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uC2MdG09;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166465; x=1755771265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=EQMs9Gxo8Fv5c51jKNoleENWxn/qtCWaIZFHF85n66U=;
        b=kOyP/IZJRqa4ZrXbbOimF/62NKRIxTo3ObqHJbYEL6F7Ax+wPGH5DpMOQaR9YdDeRf
         a2y5sJ+tRqeoBqZSuONpakAmkfxf4QXBQluEsqkdOCjpGtkE7nIim98Ta8wfEgqvA7cU
         ILSy95l9jV2VgRmP+76q6t4gOx/4DrbuuDBGNT5HnB18Ll8wOjAGZVZzB2TyYkVxJnc1
         gH5doEojQ8wMbvvedONa2AMSqmyoPkUdTgvO1HOWn+QONX6H6jRF4ClOPxuQKh9FdRnA
         vUTkQKZ1I8fglODAeC5f2ygdJp7WpamM/x5sq3oyZzDAqo0QbPjL/a07hsP+IbfaPtsp
         Cg7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166465; x=1755771265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EQMs9Gxo8Fv5c51jKNoleENWxn/qtCWaIZFHF85n66U=;
        b=uxbtkBjzZNG9uE4QKvME1nbPckBALU2WoDISEDY3FyGl5oI2NGNKo5uaVq9ixD0Jfv
         5dqK3jVNkX8Ds0JFbUB2rKjZeK6kIadOfXJQ70Yobm4EAgpVC9LV38OaaJv7AiV7w/hL
         0V0EUrbvKPjHyDFpCTqNFEW5GaeCWqb/0gh6skY3zokSSomNQC+/Jeq3PROYiUBx/5De
         b8aZZUzWBJji7xnUCMfWKAKPeJacPW+Gh70w4nqh+NO+SNwOCRFplWrhxwIsULq2ZH0l
         kUta/AZe4Tt2tGjx9g4jGy/rQWCJ+XBg4ZergK2j9p41r/1T9srnHMXvdgQMy7itVHMq
         yDxg==
X-Forwarded-Encrypted: i=2; AJvYcCXE6fwvzTVZWlHWBcUG17ffdOT/IbL3G9Dz0a4CE/u9M+VzvjCWXG5GXbevL7FbOC0fJ/Vtbw==@lfdr.de
X-Gm-Message-State: AOJu0YxmdLfjo/Cvc70lsMG9ZLc5Q5E+HBWh6wbWNL8feKR64jYbFlC6
	eiTUma5dv8ljsmKWWe5TXweFveJBwBiMZgrdoF4EYpy/Zwce/bvf6+e6
X-Google-Smtp-Source: AGHT+IGMYOHJeKmmvnUaYLFcHh1OJncZORhpX0ZNLCtpslWax3UKrF+jFIdqxP5IIBX65GhnshLg3w==
X-Received: by 2002:a05:6214:2685:b0:707:44d4:2962 with SMTP id 6a1803df08f44-70af5bd60ccmr40051986d6.7.1755166464882;
        Thu, 14 Aug 2025 03:14:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfUyHyjGkUlQC4Va937fqaQQxnhhuZZvHn49Hj606PTkw==
Received: by 2002:ad4:5aad:0:b0:707:1972:6f43 with SMTP id 6a1803df08f44-70ab7b5944dls9428656d6.2.-pod-prod-05-us;
 Thu, 14 Aug 2025 03:14:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXH7Fp3HsfR0UB9IIU98TX6ogcROWc/FXdicUnUdwNsdhIFvzg2ymt5BDcZMYXKOut/uJAUHIss/OQ=@googlegroups.com
X-Received: by 2002:a0c:f009:0:b0:70b:a0c5:5688 with SMTP id 6a1803df08f44-70ba0c5606amr1891866d6.8.1755166463847;
        Thu, 14 Aug 2025 03:14:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166463; cv=none;
        d=google.com; s=arc-20240605;
        b=Y/IjntyFys5d5fkiiMwJMonbem5wtkrg7lS8zswl218btr9ABezf2chaWf4PnNC94w
         R0ppwoq/DDhc7i/wYap9Zp5xN3a+FViBYJbPOBjquFxu5RLYdKD0T0EZeK0TyF8j5Zzw
         Rg2tUBHrmv5ZqzEA2BSJlE1ZgRv33tLEoDAP/YOI+OaYKV64RbIoV2seR8tBZsaFT3I5
         pnPf/xoZJq/VAPGNWLOqOAUaaCMJinq/wgkmmHLTlKWYJsF0TqNgXm5utmyMY5NadmeP
         SagWHQDKXnH2xmSjRU50AIL0LNaaA3xIMCQb0oZv7v0FLAM6Eh8ERi69qPwZFdfRK5x0
         khEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jrbvw9rOWoWngXahJIZ+jx/PMyl/cB74JnS12q9ePqA=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=ZUE6/4jxCrMPh2q/M3W+S9AJ2GdIZrdt/cqrHgQLvQxfoSwFbPZUBVP7sHS9Kn4nOw
         djypY+9Nv+gMr1qAxyxNfu1SR8X+YKM5YVuKctjYbq4dz4RU50Pw1I3kbao8CgAwzUcd
         6s1V8+r2Zg8Oc/+/rGXbiagcVC3JIykheR7xB6ial1Wa0VBI0MC09A3L6CVHJqO+6mWO
         jUdlCGWp99u7DH36vW8o5r0kn3fM+RKG8yevvYmrWuvbKtA5iaQmf2flqF3gHQA+uWaa
         jU1KpEAsXNNnrTyet8b3Dkm3RfLnKH5RwX1xxzga/elVCbguXRiAeD713Q4u4/MfGMIo
         Z69w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uC2MdG09;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70adc0c8fe2si949516d6.2.2025.08.14.03.14.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:14:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 1981045896;
	Thu, 14 Aug 2025 10:14:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1A882C4CEEF;
	Thu, 14 Aug 2025 10:14:22 +0000 (UTC)
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
Subject: [PATCH v2 07/16] dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
Date: Thu, 14 Aug 2025 13:13:25 +0300
Message-ID: <c9c845401023b1a1a30b500845f2979b73ea06b6.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uC2MdG09;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c9c845401023b1a1a30b500845f2979b73ea06b6.1755153054.git.leon%40kernel.org.
