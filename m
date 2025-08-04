Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB3GVYLCAMGQEEDWP6RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id D9FE5B1A1A1
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:43:26 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-76bec81c902sf2209766b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:43:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311405; cv=pass;
        d=google.com; s=arc-20240605;
        b=h9BJQBsPWQFki4Z+Rkjgle9o9xuLj+IENXsSomjX3R8vQzj0uctOLdD5jAyOSZ8GFr
         2+lMI9caz2u79c6HudmcpBz1mk5EQTNqpmnOiYV8iKzVgTdDOkyN3kXBobjr6eU0URzh
         /u5SIaffihItyDC13MKBrydnbvUGbmkvnl9Yy3SegJAvVaxkLbKcc0HrU9V9f8k8Au3O
         guC9/K1Ei+xuDOsmsuDlB6TvUxdl0580uStclcNA+jnRCD7413+UD4AtBsZ7nlu+LfZI
         n9Wbz1LnPy0MCnvI144oV5HPOeZjVAAZavAOqtmlWStv8amma1nBFQHhzFhqFUzJK1eX
         4kjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=yb8a0y2lrure84W3uc1lasD73cJ5ESvSBRkc9a1ip74=;
        fh=h8pqhM6yLdeqNQtYl/cusqqC58h57p95N2DKB59UQog=;
        b=hqchf3wbMm3w96VTSyV4IR4NtCQSArQjcMojGOZrgYXdHYr1gvvFR96c4G8dvON+yX
         lvE0a1rkygDl6HmtS431H8LNtfdllS6R8HazMI1DtgHmS5EpT4vizwv5TTqoeeDHWXar
         EGpQy3KNf7k40VvjvjFuCagUNJqDSDCglWXZg3pi0EcjQM+02L8tboUQnJb7suitUytZ
         H7gs/sEu642Xo0y7K+pJznPpSGvrn3X0x3q6ZnGxjsNqK8MWgtvAvyuj7zoErSMmFEBz
         XDUa8ZVafETHzJ9Ag2wsL6ZZlinWCPyhpLxq436o2RY5Ij3LILmw9nNMXLAvh2Dd/qcd
         ZPqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FLzGyKpi;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311405; x=1754916205; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=yb8a0y2lrure84W3uc1lasD73cJ5ESvSBRkc9a1ip74=;
        b=S0CEG6GRCXSEFgcyTLR2plM/h8mlB2byoHDFPoZklBsg3IJt7swc1oe4aTEWEnXZgC
         68DbnnyKo3SANtfQq3pUltrLhoxuhK8pyt9K5lHGm1wf8LZ1IV5eBdS3tnRqMo/X7ZxE
         L5IBntaE38Zj7W07KJ8z73Kfnf5eolDh/9cYniTcAO74Uc+u4SPLAQ9U6ABYPjAFdsri
         t1sUvZPzqXyar65KQARCB3c8R4CU973PK8MocpUXoxtoITxv/8Btc6aURV2YzOxbH8xz
         NfNhEToPKlgBxQ9vCXbWDPgLWawQRrVUC0GiO5nZOILoQds8pQkba9KAnLvP02ge9jmy
         jmXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311405; x=1754916205;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yb8a0y2lrure84W3uc1lasD73cJ5ESvSBRkc9a1ip74=;
        b=Ph4Qh1yIN+rOPqm5aGnuqZKVgkYnhm8cAVhFpGFrZ+25qLA25g6yGxBAf0q2QM6gTY
         T0bDyWO0hT5KzizZztOU1ab/I+JghMbJSmqqsObbSqaXjLNJHbEb/NTqwZh2Ljq8TosA
         A3Q6q5Ed735FT57KSUDW+1m/hU+3ytqrIDLsOAvUNRgVbFWZ7yswy5lE4iSN4UNpHvEo
         JkkoKlUKCkmpkHXo3E4DTuw4/m0vQ9n13x7It5gzv47b2c7diP+6FBwGbmlJLlGtNynA
         G4A6NFo6JMN0cRa3w8VI1AV/cOzb6ggXkESoctNaRXPHHZMDnKGGUpIoXp8Ge4DE08Ro
         WPSw==
X-Forwarded-Encrypted: i=2; AJvYcCUkWmglY8KD7SbBjmVlHSjbFGvfuwM5q0l0Y1xkuORbNmp/jkLVTRy83aiPo4X1E6Ur4RlvxA==@lfdr.de
X-Gm-Message-State: AOJu0YyNw7GXcSfOZrhyuNYlX2JJREw0v/befnyhFoyNmllX+8h0UcOp
	lnzVfkcu57HSt/XiPbQAdjPZ8fe0A+hjRdVFxtBO6SUqy3km67mlWd8Q
X-Google-Smtp-Source: AGHT+IEpuALrUFTRTfYdAb0UP62dk6AgH84VUoFifbaTULAEN8QIE8SJwxahZFAm8Ov15LOEFSUvCQ==
X-Received: by 2002:a05:6a00:39a1:b0:74e:aaca:c32d with SMTP id d2e1a72fcca58-76beaa6a266mr10416938b3a.10.1754311404771;
        Mon, 04 Aug 2025 05:43:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdYuFxKpJL2Y9Z+aNfmXF61bN3RCXvuTLKAn0Mdul45NA==
Received: by 2002:a05:6a00:2312:b0:769:bb89:eea with SMTP id
 d2e1a72fcca58-76bc942b602ls2154372b3a.0.-pod-prod-00-us; Mon, 04 Aug 2025
 05:43:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVG4hNm7Cr+HVK8aT4cwdp9aRSyLib6EiOH91HwbDOo1yiS2y03Sv74FOzqHk6nE1fLpB6euOOxt7k=@googlegroups.com
X-Received: by 2002:a05:6a20:3d85:b0:240:792:e87a with SMTP id adf61e73a8af0-2400792eb44mr5523843637.3.1754311403287;
        Mon, 04 Aug 2025 05:43:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311403; cv=none;
        d=google.com; s=arc-20240605;
        b=EIGj1P9Fvd2RJXOS5xUYB587sY1zsSj3OTP81xFdu4GGpbO8j5lEnzWmRaPonUB8zL
         RzF1Sdo//AwtKmNAKBrntDS2lZJKgfMs5iZKkaLPMWL5Tjagp8VdM1o3wC2Att0/kDmG
         J4QduBGR2Qt3BhbSzY2MGan8aXTuZi22I7+/d6XPvx6H7Z+AfcZBWPAjk9LmYTAl6fmY
         zXtz5v/hqUH6rod7eAGdFVFjdx+nem81ePMGZMS91qo49FXgq/2Xt6ap7bpTLa9j42Sv
         V4QzKTm9pnUlbRYqFxMJ2U05q0p/YiqDEMGSR0Iv5tvXXdj8fTjCIwOJPbTQXoY6pt3Z
         s8zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Y9GAfGjuophEQ7ZKuR3iSLNdSI5TrmwdTZOn2v2V0kg=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=Xonneux5nOEc1KulMoY/LcaCCaWaonl54DjaZmNWboNGpoF+qPZqGzOOYQBNk87TQC
         joG1u9ifOTHzJNbBbNlJWUcLhfYTew6zBsD7xB+N/CI3b8maGpU419RtAY0DFHAwrjdG
         yb3druQwts/Mm259xpJblKKebJOi8PkvZjWVYSLy2AsrT8jiGqf7uGTztUnCff0wXFwj
         hS3DBMO4lv+2jUvph1iWJkhkVgzwObJV87rhw1kPETTYubVha7PZA+7P0aWN92L+r4Ko
         42vyBGKTPeL2iV3pPHbKuIJnPHPN9BR1uqI71CrnbxfVHX450d4z893spK6rOQ6RFuIq
         Fkdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FLzGyKpi;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b42346fdc00si342319a12.5.2025.08.04.05.43.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:43:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 2379744938;
	Mon,  4 Aug 2025 12:43:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E414EC4CEE7;
	Mon,  4 Aug 2025 12:43:21 +0000 (UTC)
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
Subject: [PATCH v1 03/16] dma-debug: refactor to use physical addresses for page mapping
Date: Mon,  4 Aug 2025 15:42:37 +0300
Message-ID: <9ba84c387ce67389cd80f374408eebb58326c448.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FLzGyKpi;       spf=pass
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

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 Documentation/core-api/dma-api.rst |  4 ++--
 kernel/dma/debug.c                 | 28 +++++++++++++++++-----------
 kernel/dma/debug.h                 | 16 +++++++---------
 kernel/dma/mapping.c               | 15 ++++++++-------
 4 files changed, 34 insertions(+), 29 deletions(-)

diff --git a/Documentation/core-api/dma-api.rst b/Documentation/core-api/dma-api.rst
index 3087bea715ed2..ca75b35416792 100644
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
index e43c6de2bce4e..da6734e3a4ce9 100644
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
index f525197d3cae6..76adb42bffd5f 100644
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
index 107e4a4d251df..4c1dfbabb8ae5 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9ba84c387ce67389cd80f374408eebb58326c448.1754292567.git.leon%40kernel.org.
