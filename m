Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBUWF7DCAMGQEKA2ZTFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 595B4B26E02
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:54:28 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-30cce58018esf2408809fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:54:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194067; cv=pass;
        d=google.com; s=arc-20240605;
        b=k2aP3MC3ko+JohC5HfRvX+vrO7iHnQjdXUnSN7VxMcCcnIlNC7GiUnKu1/lQcLDJHc
         R/t6K2Rmlgh7oy+S1vGo3IYgZZIVrjq/VzL0MLvSsL15Ad4nEGk8WV+sg5MrPJNqVkfG
         kAv4nvZU0oNu4a9cT6zHG3cAElTR4jcCnDJt1t5zvanfJ4g0vfZEHBEDFSpbOAh9dFUc
         3qM6Z8JLUrRWKrIWQ+dKhqbI70lCht+Camj7nm3JcChDqsbS0LjqXTrHsv4J8q2hUF/C
         vYqAN/kTTYrHUBj0uQGMI8pWzMbf5eZLtTJzO06wcpT+Kbip5O/Z1AN6xEoCm/6jTgTa
         ITdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=WfnHugYqsVohiMRNcJteuTbGOD1Vm16gWgrW50EUdCU=;
        fh=XyAjflL1Cje8KLABKWmlrADFvDN/VaZPAGGV3Xnya+8=;
        b=i4380pAI3ttsKFkxm3vyWhQ8DIPhjd118ASTMsRIACI7aAUXXK6bhHulKDonnCSnW7
         PK9amWa/1Iqt/rOn17lQMmcYUXxk0ECWHHBO93FtNQMWBX2/2X7paj12fAWVXhJyUDKF
         ae1WExHyhQncV0Kq2kLWdGzRstbmt+8xyHH49t82vaCUGaJUS+KG+lzUn8T3pM8sS5XI
         qY+zS0P3mc4BfvLgWEALx9b1JkvVKirRZZ7Uh5IFd/WPPGrMGH8oo3kgHmkw6fNagxYe
         W5aQxzxayO/PamvyIbdLYw43KpgZCaSsEwtwxP3xV1fJE9BoMNJOgAJqNBP+UFJJn0mc
         k4YQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SSyTqHjt;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194067; x=1755798867; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WfnHugYqsVohiMRNcJteuTbGOD1Vm16gWgrW50EUdCU=;
        b=PGnMTEQk0lYoEva6/pNF36LlOSA5LRDX5+2SU18TIloGsVmSs+xFWkZ6qJ08F3PgnY
         Y2FA9qf7GPZyQwXyjd6iVsX1xMqnsm1WQx1N3CSVzGTT/59uTgJGNHJXJAX1CqzxRoVv
         Oun3GRRHZvt9k3HjqgCkhLznywTFqvT0G+lYXwjgXsnXwk0cMR73wXtnznEok7Dm26vU
         PT/pV2c3zOhagDmdggRjEGnjUOryy8wZNrISkOCmd0Ynt+RoDZGqT3CfVpVIJvhsUut6
         8+qjcevItXNMRd3CMnTGpi8h+YO68d5qFyE6Jr9EovCiJitAcumv4V/SL+V01A0t9rxH
         wXdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194067; x=1755798867;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WfnHugYqsVohiMRNcJteuTbGOD1Vm16gWgrW50EUdCU=;
        b=sycLiYDNubpleT0jWLDzk7eYXpLyv8sOfQwTUZgxwef2vCKBu4D3eEDO8+OQL9S91k
         6x14LKTjP2HJgOnfvi5bHrgTSiEe05krCPzMNIiVS+3nX7tXMwSSIHdnFUizp6l978/C
         hUZQj3F03FQAQdvcPaETYpg6n3jfDWB9Ypm5XXyXOa+XKl3mGJePLhWRg7DPY8qbCQWu
         Ph2cbHXgygykmmjaVgQwuwIKdtigRB+duBHZo3sq5ZCz8lgnAhu73l96OJ9nUWH0WYbL
         8UMwqiUoJRnSdbebZj7F7kn3dwiqOEJpdG3IIQiX1GId+OdEsJKFNAc+BsThUKWA2qkr
         MDqg==
X-Forwarded-Encrypted: i=2; AJvYcCVog1Paf8NoNJlOvEDgrIMcWI1E5kYZ68eqSsUvZihlwgxuxPep/fGSWHyPDsxCnSmSjNsS4A==@lfdr.de
X-Gm-Message-State: AOJu0YyLt6Xo/2+KZLC+DXejVDeGYxpvSRnBl2Gsn0QQh8lhv626vch5
	SLyRr9OzsP1G8BcY9ZcatPi8OIioPU/7fsoIO67p9WLmzu3kTuD0SIbC
X-Google-Smtp-Source: AGHT+IFp6NugXobffWDPtWsFDq684q6P9S3YXYV5Gg3jh1vF4BPeYoYjd88Obtj5t1RcykAZ0ReVVQ==
X-Received: by 2002:a05:6871:8917:b0:30b:75a2:a45e with SMTP id 586e51a60fabf-30cd1383599mr2777217fac.33.1755194066784;
        Thu, 14 Aug 2025 10:54:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfc9FXBvL/QwZxDaOyYcL4KG5+HGDkr/+yvg+Br3ZZj6g==
Received: by 2002:a05:6870:d152:b0:30b:c2b3:2130 with SMTP id
 586e51a60fabf-30cceb68b39ls739179fac.1.-pod-prod-05-us; Thu, 14 Aug 2025
 10:54:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWrNOnYnSpVkZ6MZim5Cn2uwmG2sIxPbbr9EOPSo6E/LkKBESOReDEOnKaLLD+zWoU4OXvw1x1vzIw=@googlegroups.com
X-Received: by 2002:a05:6808:3a16:b0:40b:555b:9024 with SMTP id 5614622812f47-435df6f5af6mr2855361b6e.17.1755194065091;
        Thu, 14 Aug 2025 10:54:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194065; cv=none;
        d=google.com; s=arc-20240605;
        b=Or3bmtTPhskgVeqqVW9d4R3jpR29dkZN/Ch9oY47BZB1L/H/5asO/Luy2hbGB1jGA1
         FP2/lTZP/3YyEIfhJGi//xNWShCARjnN6a9+D3KpZ0K1AvYW2/HtRyTNF0TEkkO5OGcJ
         pfrCOEUtULoqHYeJfQeAPNduZkTq+Qh03vGTj5WUxMGE1oTpCtuIeW5F5gG2wmH7+Ui2
         atqunYGoZmqqSzKxwkmDaf8a+ZbLRvgPj5DoU4rE9rqNzAMXK+GpbstT55ju79beAYln
         JBqCUZRpVk8aNEsknrkxLoaw2Dti76ndn3vRyKlqmf/RX28Bm+RtVkFcl3WeKE038+e2
         m3ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XfxLLKvH/DpVc2NbZowrmc3+FoU4H0K6l6sYGFFyH/0=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=fXeHEcUtI0cO5iQ7kyCk7iO+niTpfJAk4S66gEOw6vLSKrAqlUe3U67hyNitXYhxSR
         rK8QNXY3o//mRaNf1zJP/mAOPdnIyyp4GQoDVaLaklWPGR6BouL8g7yYkun4IjnczTwC
         qm7VTc0G19OpU9FpkhYaFIorcrNfaLFnboB693+NjFJuZaETy5B1L3MMlyXgFfnHBoh3
         02ylWqxGpifOiiILOIrUsEjcIdBRg8kBW3o349GOp4FEJy3RMmZZ/osg/mwfAtmIvbNR
         dPhxMpE8aHLRX+YOmJtrhX6s5dMPDJrw6XttgXDWqnRXzWa/sqtidiXDsmXC38mGkyzn
         f0vQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SSyTqHjt;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ae9b6cc7bsi596340173.3.2025.08.14.10.54.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:54:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 6F76E61133;
	Thu, 14 Aug 2025 17:54:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 541FFC4CEED;
	Thu, 14 Aug 2025 17:54:23 +0000 (UTC)
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
Subject: [PATCH v3 03/16] dma-debug: refactor to use physical addresses for page mapping
Date: Thu, 14 Aug 2025 20:53:54 +0300
Message-ID: <478d5b7135008b3c82f100faa9d3830839fc6562.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SSyTqHjt;       spf=pass
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

Convert the DMA debug infrastructure from page-based to physical address-based
mapping as a preparation to rely on physical address for DMA mapping routines.

The refactoring renames debug_dma_map_page() to debug_dma_map_phys() and
changes its signature to accept a phys_addr_t parameter instead of struct page
and offset. Similarly, debug_dma_unmap_page() becomes debug_dma_unmap_phys().
A new dma_debug_phy type is introduced to distinguish physical address mappings
from other debug entry types. All callers throughout the codebase are updated
to pass physical addresses directly, eliminating the need for page-to-physical
conversion in the debug layer.

This refactoring eliminates the need to convert between page pointers and
physical addresses in the debug layer, making the code more efficient and
consistent with the DMA mapping API's physical address focus.

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 Documentation/core-api/dma-api.rst |  4 ++--
 kernel/dma/debug.c                 | 28 +++++++++++++++++-----------
 kernel/dma/debug.h                 | 16 +++++++---------
 kernel/dma/mapping.c               | 15 ++++++++-------
 4 files changed, 34 insertions(+), 29 deletions(-)

diff --git a/Documentation/core-api/dma-api.rst b/Documentation/core-api/dma-api.rst
index 3087bea715ed..ca75b3541679 100644
--- a/Documentation/core-api/dma-api.rst
+++ b/Documentation/core-api/dma-api.rst
@@ -761,7 +761,7 @@ example warning message may look like this::
 	[<ffffffff80235177>] find_busiest_group+0x207/0x8a0
 	[<ffffffff8064784f>] _spin_lock_irqsave+0x1f/0x50
 	[<ffffffff803c7ea3>] check_unmap+0x203/0x490
-	[<ffffffff803c8259>] debug_dma_unmap_page+0x49/0x50
+	[<ffffffff803c8259>] debug_dma_unmap_phys+0x49/0x50
 	[<ffffffff80485f26>] nv_tx_done_optimized+0xc6/0x2c0
 	[<ffffffff80486c13>] nv_nic_irq_optimized+0x73/0x2b0
 	[<ffffffff8026df84>] handle_IRQ_event+0x34/0x70
@@ -855,7 +855,7 @@ that a driver may be leaking mappings.
 dma-debug interface debug_dma_mapping_error() to debug drivers that fail
 to check DMA mapping errors on addresses returned by dma_map_single() and
 dma_map_page() interfaces. This interface clears a flag set by
-debug_dma_map_page() to indicate that dma_mapping_error() has been called by
+debug_dma_map_phys() to indicate that dma_mapping_error() has been called by
 the driver. When driver does unmap, debug_dma_unmap() checks the flag and if
 this flag is still set, prints warning message that includes call trace that
 leads up to the unmap. This interface can be called from dma_mapping_error()
diff --git a/kernel/dma/debug.c b/kernel/dma/debug.c
index e43c6de2bce4..da6734e3a4ce 100644
--- a/kernel/dma/debug.c
+++ b/kernel/dma/debug.c
@@ -39,6 +39,7 @@ enum {
 	dma_debug_sg,
 	dma_debug_coherent,
 	dma_debug_resource,
+	dma_debug_phy,
 };
 
 enum map_err_types {
@@ -141,6 +142,7 @@ static const char *type2name[] = {
 	[dma_debug_sg] = "scatter-gather",
 	[dma_debug_coherent] = "coherent",
 	[dma_debug_resource] = "resource",
+	[dma_debug_phy] = "phy",
 };
 
 static const char *dir2name[] = {
@@ -1201,9 +1203,8 @@ void debug_dma_map_single(struct device *dev, const void *addr,
 }
 EXPORT_SYMBOL(debug_dma_map_single);
 
-void debug_dma_map_page(struct device *dev, struct page *page, size_t offset,
-			size_t size, int direction, dma_addr_t dma_addr,
-			unsigned long attrs)
+void debug_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		int direction, dma_addr_t dma_addr, unsigned long attrs)
 {
 	struct dma_debug_entry *entry;
 
@@ -1218,19 +1219,24 @@ void debug_dma_map_page(struct device *dev, struct page *page, size_t offset,
 		return;
 
 	entry->dev       = dev;
-	entry->type      = dma_debug_single;
-	entry->paddr	 = page_to_phys(page) + offset;
+	entry->type      = dma_debug_phy;
+	entry->paddr	 = phys;
 	entry->dev_addr  = dma_addr;
 	entry->size      = size;
 	entry->direction = direction;
 	entry->map_err_type = MAP_ERR_NOT_CHECKED;
 
-	check_for_stack(dev, page, offset);
+	if (!(attrs & DMA_ATTR_MMIO)) {
+		struct page *page = phys_to_page(phys);
+		size_t offset = offset_in_page(page);
 
-	if (!PageHighMem(page)) {
-		void *addr = page_address(page) + offset;
+		check_for_stack(dev, page, offset);
 
-		check_for_illegal_area(dev, addr, size);
+		if (!PageHighMem(page)) {
+			void *addr = page_address(page) + offset;
+
+			check_for_illegal_area(dev, addr, size);
+		}
 	}
 
 	add_dma_entry(entry, attrs);
@@ -1274,11 +1280,11 @@ void debug_dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
 }
 EXPORT_SYMBOL(debug_dma_mapping_error);
 
-void debug_dma_unmap_page(struct device *dev, dma_addr_t dma_addr,
+void debug_dma_unmap_phys(struct device *dev, dma_addr_t dma_addr,
 			  size_t size, int direction)
 {
 	struct dma_debug_entry ref = {
-		.type           = dma_debug_single,
+		.type           = dma_debug_phy,
 		.dev            = dev,
 		.dev_addr       = dma_addr,
 		.size           = size,
diff --git a/kernel/dma/debug.h b/kernel/dma/debug.h
index f525197d3cae..76adb42bffd5 100644
--- a/kernel/dma/debug.h
+++ b/kernel/dma/debug.h
@@ -9,12 +9,11 @@
 #define _KERNEL_DMA_DEBUG_H
 
 #ifdef CONFIG_DMA_API_DEBUG
-extern void debug_dma_map_page(struct device *dev, struct page *page,
-			       size_t offset, size_t size,
-			       int direction, dma_addr_t dma_addr,
+extern void debug_dma_map_phys(struct device *dev, phys_addr_t phys,
+			       size_t size, int direction, dma_addr_t dma_addr,
 			       unsigned long attrs);
 
-extern void debug_dma_unmap_page(struct device *dev, dma_addr_t addr,
+extern void debug_dma_unmap_phys(struct device *dev, dma_addr_t addr,
 				 size_t size, int direction);
 
 extern void debug_dma_map_sg(struct device *dev, struct scatterlist *sg,
@@ -55,14 +54,13 @@ extern void debug_dma_sync_sg_for_device(struct device *dev,
 					 struct scatterlist *sg,
 					 int nelems, int direction);
 #else /* CONFIG_DMA_API_DEBUG */
-static inline void debug_dma_map_page(struct device *dev, struct page *page,
-				      size_t offset, size_t size,
-				      int direction, dma_addr_t dma_addr,
-				      unsigned long attrs)
+static inline void debug_dma_map_phys(struct device *dev, phys_addr_t phys,
+				      size_t size, int direction,
+				      dma_addr_t dma_addr, unsigned long attrs)
 {
 }
 
-static inline void debug_dma_unmap_page(struct device *dev, dma_addr_t addr,
+static inline void debug_dma_unmap_phys(struct device *dev, dma_addr_t addr,
 					size_t size, int direction)
 {
 }
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 107e4a4d251d..4c1dfbabb8ae 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -157,6 +157,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		unsigned long attrs)
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
+	phys_addr_t phys = page_to_phys(page) + offset;
 	dma_addr_t addr;
 
 	BUG_ON(!valid_dma_direction(dir));
@@ -165,16 +166,15 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		return DMA_MAPPING_ERROR;
 
 	if (dma_map_direct(dev, ops) ||
-	    arch_dma_map_page_direct(dev, page_to_phys(page) + offset + size))
+	    arch_dma_map_page_direct(dev, phys + size))
 		addr = dma_direct_map_page(dev, page, offset, size, dir, attrs);
 	else if (use_dma_iommu(dev))
 		addr = iommu_dma_map_page(dev, page, offset, size, dir, attrs);
 	else
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
 	kmsan_handle_dma(page, offset, size, dir);
-	trace_dma_map_page(dev, page_to_phys(page) + offset, addr, size, dir,
-			   attrs);
-	debug_dma_map_page(dev, page, offset, size, dir, addr, attrs);
+	trace_dma_map_page(dev, phys, addr, size, dir, attrs);
+	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
 
 	return addr;
 }
@@ -194,7 +194,7 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 	else
 		ops->unmap_page(dev, addr, size, dir, attrs);
 	trace_dma_unmap_page(dev, addr, size, dir, attrs);
-	debug_dma_unmap_page(dev, addr, size, dir);
+	debug_dma_unmap_phys(dev, addr, size, dir);
 }
 EXPORT_SYMBOL(dma_unmap_page_attrs);
 
@@ -712,7 +712,8 @@ struct page *dma_alloc_pages(struct device *dev, size_t size,
 	if (page) {
 		trace_dma_alloc_pages(dev, page_to_virt(page), *dma_handle,
 				      size, dir, gfp, 0);
-		debug_dma_map_page(dev, page, 0, size, dir, *dma_handle, 0);
+		debug_dma_map_phys(dev, page_to_phys(page), size, dir,
+				   *dma_handle, 0);
 	} else {
 		trace_dma_alloc_pages(dev, NULL, 0, size, dir, gfp, 0);
 	}
@@ -738,7 +739,7 @@ void dma_free_pages(struct device *dev, size_t size, struct page *page,
 		dma_addr_t dma_handle, enum dma_data_direction dir)
 {
 	trace_dma_free_pages(dev, page_to_virt(page), dma_handle, size, dir, 0);
-	debug_dma_unmap_page(dev, dma_handle, size, dir);
+	debug_dma_unmap_phys(dev, dma_handle, size, dir);
 	__dma_free_pages(dev, size, page, dma_handle, dir);
 }
 EXPORT_SYMBOL_GPL(dma_free_pages);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/478d5b7135008b3c82f100faa9d3830839fc6562.1755193625.git.leon%40kernel.org.
