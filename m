Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBAWWYLCAMGQE65SRPPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 83904B1A1AE
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:43:48 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4ab878dfc1asf102748121cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:43:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311426; cv=pass;
        d=google.com; s=arc-20240605;
        b=j7lau710liB60cYuAxjkiLSm5L2h29EvZF8awAImeNzuK+vY+aQR1BgbFXQRNSSLy3
         hHRK1Iud9JyVn6I4+lOQL13MoAYFMC9Awits95CCB/mo9v8+1NbHH+pwPhMwD6crtbMb
         qir+CQ/Bm+WbtY2RDb9JdxSsfdbot7q7PPcWxxX5CuHg1bD3Kt3NbKm3cAScC9hdwHyI
         xvpl+DgrVS/6SV4ZrS4WGk8xXMR98VU/6XFLzHFalIqDjp590dye49ylnAWZnekHWWwH
         dcPRCbVjvjQZXfhwJN3H7ZH9BOn0nbfKK1VzUwb0MSapf6TZQAISs5hYkX+8/HMrWWta
         nkdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=G+DRWVEYZ4i259tqlGm/rRfGK96YKmf9/lxjxegaAvQ=;
        fh=Bk0x6uGCpp93mhTfYRjT8UluHe7APcrnfFtLGFVpOlo=;
        b=ToHO5qvcxe6oK+0vHUvva5slTQ7yxh7rVi0lR3uJyg7Uvf21rzrT+p93QIQ27SfYhf
         XYqISx44WgXq/wTvdm5vRlsSx70k7bUy/4sse9dN8mVYLd8Dy6p86007nGA+SBKKe/2O
         N3Z5PXaYiNO7xUHdQDNExCDtba6cx9mcyvHOSJ38deZ0hXtODcrg8GlRSL0T0/LMcUds
         jC8GICMGiEGLvZvX1jS3wPpsWag+YZzQ7v8u9fnArlzmrQw6YtiGfYylalAXsAWDyb7L
         +3rrXUegoPt+n42wtM/NcYSl/Bh6ep+360u2tEjK5qQrQnEy9g2eSWRzFFaCjYPU1DH0
         NYNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sRzNIswy;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311426; x=1754916226; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=G+DRWVEYZ4i259tqlGm/rRfGK96YKmf9/lxjxegaAvQ=;
        b=jWNX/U+rDpNR4Wwwv0AEhEK7Ay6NHmE2Xli/vPmsZdtU1vTIB2Jf/ZAAV3kBu/K+0n
         Z4lSF2kkWGIhAf/GAsosnV15Ayq81CMN5Mdm6awqfGF2gMFlGZov3XbpFxtd6x55C2a9
         skxUE7P6FANAev6MqxD7/g63Cvx+39HPLAqN93YB2wWd+SVxNrzdUTx0mjcMuwElpViW
         j5QVbmYB6DwkhXvbG62TPGSZbSHxnsBOvfee+4vk2rrpK0h955YiEtpliv71/drO3qwF
         9ICGLa/54t2mprJRTS3cSFxUACnQdXqOPQKzJjg0JUh/wr0ck/Fpxwp7/QPBLsjwzdn8
         vTQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311426; x=1754916226;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G+DRWVEYZ4i259tqlGm/rRfGK96YKmf9/lxjxegaAvQ=;
        b=Oe0TG8h2ErrPujG/2TS4uqVrujX7ccNzqdwZnZe3ZmxlOREyIpQJTzDgYoV0BOnn4H
         f6pbxlmIRmKj7Na0RMTIsZw4crD29wZwrOvFBKMkX4hJzsCu6pFWOpX87J+DwuC8S2yP
         cm7cGgKt+HTlQZ+GYsbhuhAaJba9xhgEnZ3j+c2CXqRGFFhN/KXlJagRN4cx+5TTS1kk
         ReghcoScSLnGJABffocAyTFtPMTDrrOXzFWXGj9U85mi90fpU5kThWdndFBZODMDgpZy
         6vX7ZRtomY5wwH6u0RsDGeJpyRJee5G7v3CmhCUs5xodDVzio/2BovvC3eKV54NYzJDk
         aOug==
X-Forwarded-Encrypted: i=2; AJvYcCUcEGCFPkHGtkgUdCpqgA5xxJZAtBrsl7YkrPr0QrZteUDX5gpxZlFKRaCYShWBJbvAhmBdoA==@lfdr.de
X-Gm-Message-State: AOJu0YzzsvXXAfd7E7BfI6dmUATKLnSqhbwdz2xz3R9Az8gvztlZhpSW
	Ecprx7gUntM1M5tdkkkeSQDXzappl+h3MWJQztpyuSMH1m6xYQl0ISF9
X-Google-Smtp-Source: AGHT+IEL2TMwk+6aDNFvdQaXE+TefoF0ZrM+/WqpS6J3vNWYv/xOQgAL3FpE0LkjeCF4xbjpWDhBzA==
X-Received: by 2002:a05:622a:229f:b0:4b0:77d4:ec1e with SMTP id d75a77b69052e-4b077d4eee9mr16955351cf.3.1754311426374;
        Mon, 04 Aug 2025 05:43:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcliH98fYzu1OQkbYPcHyXEfZJQYOlj8NZ9ninTdgEoVw==
Received: by 2002:a05:622a:18a7:b0:476:7e35:1ce7 with SMTP id
 d75a77b69052e-4aeef03d43dls61395771cf.0.-pod-prod-03-us; Mon, 04 Aug 2025
 05:43:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVj+8UgO7ILzof990fhmipXmhUaCBJA+B+6B5L1hnbR1fjW/5U77Cc9IvhtFlmZBaoPtB2F0/XRGSc=@googlegroups.com
X-Received: by 2002:a05:620a:1002:b0:7e6:3c25:b69b with SMTP id af79cd13be357-7e6962758b8mr1225623585a.13.1754311425336;
        Mon, 04 Aug 2025 05:43:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311425; cv=none;
        d=google.com; s=arc-20240605;
        b=A9NUlil7dY6wO+kB+sFdCrCZ2thL9lHHyzTRk33EidCRt6fc87jLIWdYeWXMmI1bYR
         v6lRuJuY97Y1XbsILtWSm80b0/jZn45e4DaZl4YM3WaBU06Rcrvi7PamxNoSbG/AEuUB
         /WsilqaIi6srppDGAQF3l4mxiIMJ3Nn+7e72cb1w2Lw/112gejZ9plKSm78iNSJC9mxr
         gjhdFD7NFxiS+uezX5RORQHawNhvzmOHXNmNrRW0yyrF7XK3JFPUsanVvcvRXqlIZQH4
         stLf7QVH0cDNChP5UIZ9rfKXlLc8tPl9YxaZ2664Y6GYXQkoWDmMvf2jkwE8xQttg4Xa
         xhyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=u2ZFZgNbfoXn5jH3X4iUOrDOvE7XGwUp7euhaxLVE2Q=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=i5Uy/bk3nmjxqT3e/+4pyU/SFXx6ejkzGdhKGfubPj9L2g64TdA2CRSQ3r0RpuQ+2j
         G1Tb1h+wtlwyag1VIqe01GDeNKYGRG0YF9lwBifE0lONhueCqOilsVL+p1hP0QHoJVID
         uTuFWMkRRlZmpIHHR1Dwnb6ghTZY4nUWR/RbjSL8lzS8eAWkJDi3EU6CESXhoLP3GQml
         1kuB7rO0/hzN9BBq9XMraOOmWj1BFTpuoFsq743ucqXj+sIe2PEX8j8hxsZ1aJhBvfuq
         Kk3vsjbesXjtqYygIleQGoUsjyAee6EZNGKYrIUSPc+TDHPWBwtAV3r4mO/Gc0iBeLra
         r/Pw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sRzNIswy;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e7fe360ea4si9271685a.1.2025.08.04.05.43.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:43:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id AE031601FD;
	Mon,  4 Aug 2025 12:43:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9423FC4CEE7;
	Mon,  4 Aug 2025 12:43:43 +0000 (UTC)
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
Subject: [PATCH v1 07/16] dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
Date: Mon,  4 Aug 2025 15:42:41 +0300
Message-ID: <882499bb37bf4af3dece27d9f791a8982ca4c6a7.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sRzNIswy;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted
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
 include/linux/dma-map-ops.h     |  8 +++---
 kernel/dma/direct.c             |  6 ++--
 kernel/dma/direct.h             | 50 ++++++++++++++++++++-------------
 kernel/dma/mapping.c            |  8 +++---
 5 files changed, 44 insertions(+), 32 deletions(-)

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
index d2c0b7e632fc0..2b442efc9b5a7 100644
--- a/kernel/dma/direct.h
+++ b/kernel/dma/direct.h
@@ -80,42 +80,54 @@ static inline void dma_direct_sync_single_for_cpu(struct device *dev,
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
+	bool is_mmio = attrs & DMA_ATTR_MMIO;
+	dma_addr_t dma_addr;
+	bool capable;
+
+	dma_addr = (is_mmio) ? phys : phys_to_dma(dev, phys);
+	capable = dma_capable(dev, dma_addr, size, is_mmio);
+	if (is_mmio) {
+	       if (unlikely(!capable))
+		       goto err_overflow;
+	       return dma_addr;
+	}
 
-	if (is_swiotlb_force_bounce(dev)) {
-		if (is_pci_p2pdma_page(page))
-			return DMA_MAPPING_ERROR;
+	if (is_swiotlb_force_bounce(dev))
 		return swiotlb_map(dev, phys, size, dir, attrs);
-	}
 
-	if (unlikely(!dma_capable(dev, dma_addr, size, true)) ||
-	    dma_kmalloc_needs_bounce(dev, size, dir)) {
-		if (is_pci_p2pdma_page(page))
-			return DMA_MAPPING_ERROR;
+	if (unlikely(!capable) || dma_kmalloc_needs_bounce(dev, size, dir)) {
 		if (is_swiotlb_active(dev))
 			return swiotlb_map(dev, phys, size, dir, attrs);
 
-		dev_WARN_ONCE(dev, 1,
-			     "DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
-			     &dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
-		return DMA_MAPPING_ERROR;
+		goto err_overflow;
 	}
 
 	if (!dev_is_dma_coherent(dev) && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
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
index 58482536db9bb..80481a873340a 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/882499bb37bf4af3dece27d9f791a8982ca4c6a7.1754292567.git.leon%40kernel.org.
