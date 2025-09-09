Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBCOXQDDAMGQEMZUXS5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id A8F93B4FCCE
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:28:43 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-32811874948sf4893715a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:28:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424522; cv=pass;
        d=google.com; s=arc-20240605;
        b=NOKv+XnNZq+qbABckT4OLSBu2HXeND/tiNQIiM8jZAzqxaeJHVcvkGBGNvvGgWx8od
         aZBizYWbbotOWn1F3sj8Yxd7RXb1t3ASTU9937l/ukliLqmgmIvHxf7tu1aT088FDcbm
         bMOpT2cMR6CmiMvj1Dl/zfbt/B2ayHLmNoAwzL6Vqg9qS9eo1Agc369RLGGqiUuxk67a
         JjcoQQvQ6rK+y6RuDgo4NaS2E/SJPrTHH0GPuR6+7I7F1pznHvKBZY8iTJJJZ1lPvaTM
         kwmCzusdv0dRczp0wlkfxFCX1om4TUKR0BRabSojGO+iCnRFFZWoVJdF0LcXxPMEdLjH
         EPWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=zNlQyn4jBn6KtA/M8xsFcEprHWk70Eme3jlZutVTH+0=;
        fh=sq+cmNBlggkYkxYySDjgmFCj7AJQxZFd9pzaIeLcqBo=;
        b=I7CBom312ENw74LnyCB6ejjdFhTZi7E5by2MnkFM0Mi4JackbSyIzwgd3fZfkIoUFN
         JKN4ruyxfzJzTWTw9M07+xKY68kNlbfkfx3jiUs5gDOPFZVy/tXzCdyQWZ2WuK8PggQy
         ibjkla+PqB4CvuuZAoHkamSyMNBNOnqD1cWhw5wFujlszh9jbp3fhxv0A7N7RfrUXWL/
         3LXwOau1e+HNYh0jI6gTNOPmcfxxVLDgzbTycA3ot6Z0p8muz6QrpwMxJdwPeCVaiM8F
         U+F4r0SFN3P2S+LSxyakq4N2lfkDcg7wu8DEuy5G8tCJFamQHcUJf1M1eVUJeg0HKJWH
         NVjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H0K5skJh;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424522; x=1758029322; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zNlQyn4jBn6KtA/M8xsFcEprHWk70Eme3jlZutVTH+0=;
        b=jaHYK91sTr1o/7TxTmWBZdPpd9Kih5f0rUkWMZsKWOb02CMIWg6RoqKraXyd/zBgzr
         q2W/AWsyLimPOdIPa1NjHOSlUqIcYEmTLndbxjTb239sZ6a+PbPSubwmMSl7fp+gNzLD
         tYzCILFMdZ64XG2izjg1E63h3bPdEuQ51Y7mEjZVvPSdK7dIWQYGhiqW5uH1cqU3jdex
         SzH08lFLL/ZZuMJq4wFw1IYejcS4El3PZj3B9OTFKwe3WCrkv8RkW7RJKAZn5ty3fT2q
         4f2hjk/kAAGaO8dYE///Hy803WAS3nxrk9XL8wLzMiDi9w2CaPCGLd24TlD48S5jwrSj
         hbvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424522; x=1758029322;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zNlQyn4jBn6KtA/M8xsFcEprHWk70Eme3jlZutVTH+0=;
        b=T2T/KK6cVMEFr2szFzsBy0DIGjZhNK6TOk9BY0FFCkk2TVaRs3VwBnp+oTBz3gw+66
         pPVXc9xwEr9GtyQnQcJFA6SqaJWevUIb8fIGlKlhIfMYIbyE/xgjgVeoaXxUHB65Y7CW
         8RrODpAxhhAKoOZDA0v7nPQORzQhLS944dZVZebiIo+7QoLm6TUH2WDoCWLZTpAomQzn
         gwZKRJTvudU3sUZm4GepqJyeIR/FMl775QGLSqFw4+AA79/j4TVd0q64ldyKYIN+WhUT
         sOUmOVru/LVgQuAtK2rUPa4yhy0rbfq+ry/dCek0aaFytlfTm+M/vkDeefI/Wl2elD7d
         Rjpw==
X-Forwarded-Encrypted: i=2; AJvYcCUk0TrZbSFX8pp3uzWZK52bDJkqjNpwnZo4JXMZdMQ3Dfle7zf+E5aygGBSYEZRm7E9AdtWhQ==@lfdr.de
X-Gm-Message-State: AOJu0YzUvvJsAEBvD59CCecjZ0rtpGh00EmoZAfwmmApGlJZv55uep6X
	yYsWNVZOCJjI72nJYN2t7dRexTaB+zkbIM+No72EZRDqNPmhFcHcDEh6
X-Google-Smtp-Source: AGHT+IGZ+WLRYjDAQCH1Oqeida14XRy8juHu9ejIbBXd4C5w0vzQVxrNe6Ve8njU+/+yTXrRgEjWqA==
X-Received: by 2002:a17:90b:1dc4:b0:327:e9f4:4dd8 with SMTP id 98e67ed59e1d1-32d43f2f4b6mr17624287a91.10.1757424521684;
        Tue, 09 Sep 2025 06:28:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd48CNCqkOTrkXJALWke64RhuJvmTh+kSa6rq+Razp9qOQ==
Received: by 2002:a17:90a:d005:b0:32d:36f0:e621 with SMTP id
 98e67ed59e1d1-32d36f0e630ls3721776a91.0.-pod-prod-05-us; Tue, 09 Sep 2025
 06:28:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFPsvMVvu9720lOuXAl9VxrN7rATBevyuQ2PBN42/fyzVM0cWjIHJDi4trOcJGcykXPwa066/k6yA=@googlegroups.com
X-Received: by 2002:a17:903:2348:b0:24b:270e:56c0 with SMTP id d9443c01a7336-251734f2eb0mr182510395ad.36.1757424520050;
        Tue, 09 Sep 2025 06:28:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424520; cv=none;
        d=google.com; s=arc-20240605;
        b=cY5IK9+W7NtP86AuqB4EekoEfJrfkAPcytkPNG9hw5ydF/pS03Mi6kQTuamgtByAgi
         IAs8OKAenppe5fwNigR9eZ0ssuG3EUX9bs1lPFUUI842XNtbJV9yQXXcUg+CMESjKYQW
         A7ersHBm08yC4Yxyuaalj6+fLJT/NtQcAiJmb/2/3nkunAWk2mT/g6VHrsS96IhD80hn
         mEMktQZqi6x0oQY44wmO8q0GCvGzdER40UK+7gsosT82lQxDo7yXFh78AtkH8NFVAXHD
         iLCzHPykVhDKuCtCzEqb9T3nFPkT0u2hpnbm+GNjQ0Grp4kVSkEhMfBFIuX+gfNwpldr
         R5uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0ox0T3nJrZzkkPKbqSqfbPUkq1ORzYA1qjjFfdvCJIM=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=Rx/KM7oAg6cJrNM2CoWtf8TgYw4gnLK4DErzMjxO6+jPyJWm39p6tErncEZTgb7dw9
         GKCSJl1fgv/HkfQJRYB327SBsbT+/TYM2BxcWTKLmcLhdsEdQUG/fZ0/FIrB4WF2qmCo
         t1a+7RMJR9j5sCQb99PSk3C65OuIVRz3HlkqGGhU1bzyNJ2KP5YWi6Y0v33Kk4aWGkhz
         d+Tx/bty7XazLruQKGgu670R06o819ofd0vcv/7/7TyRXjeG1x9z/Gsww/D27NjFXd1c
         I/9dmDWIadJ/0bv5uaJfE9AJN1fBdtzbhsQhlikeFktMka4w56WQishjmWMIo2CMUd71
         EwVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H0K5skJh;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-24c822e3707si7939525ad.8.2025.09.09.06.28.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:28:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id DABBA443D0;
	Tue,  9 Sep 2025 13:28:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5AFE4C4CEFA;
	Tue,  9 Sep 2025 13:28:38 +0000 (UTC)
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
Subject: [PATCH v6 07/16] dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
Date: Tue,  9 Sep 2025 16:27:35 +0300
Message-ID: <bb15a22f76dc2e26683333ff54e789606cfbfcf0.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=H0K5skJh;       spf=pass
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
index 4d64a5db50f38..0359ab72cd3ba 100644
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
index f48e5fb88bd5d..71f5b30254159 100644
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
index 24c359d9c8799..fa75e30700730 100644
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
index d2c0b7e632fc0..da2fadf45bcd6 100644
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
+		if (unlikely(!dma_capable(dev, dma_addr, size, false)))
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
index 90ad728205b93..3ac7d15e095f9 100644
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
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bb15a22f76dc2e26683333ff54e789606cfbfcf0.1757423202.git.leonro%40nvidia.com.
