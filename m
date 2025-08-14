Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB6HN63CAMGQE4IB5WPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 34353B261FE
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:14:18 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3e56feb467csf9249115ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:14:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166457; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qrk6WHEagawjQfA8Jur99zZyn22nxXQstYceBa1weE1AhcsE0FA1IGp0wqpoyK7iHB
         lFGIE+DX2pJ5UVH1FEctJGqmSrxZu+DPVJxqOzdhao2iD7GKCHYRoKunXnVQquRmmFGx
         6N3kHY1sDvZNRXxg8EmVBoQnrvDQ0EvAyT/bzAJx5Lynsf8IqG2IxpIXRjxu5MMAD6Op
         CHTCcFKbpvfIGCCfEVd5HCYhCFTwm3XP5LuJEdOSjMpb8LcLTeemAid2cjZPCVvU/wxC
         ouz2j+rHZEn02O0JP5acpfpc9nIsi9xWD+2+O/NQMuJzA7HIyg9uEXr0arXNoOGvr8b4
         dTfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ApgCPfXJ0w1AUCwa+ltrVr0IO8tJ03abLfbEZpAP3So=;
        fh=VYa3HkmVGGmtw34h5+XNHbR381s8CaQk5SimHkmVTTg=;
        b=JxbZfviOZc6eSUSiTc3jTpaKm7ztMPo3dDawW1ObBsCefVuT0rcm9oVeTL4vpjvi3i
         4l8M686fMrlVYA2wZ+zsqe4pYYm2Pifa7ICVOj+InnzqrksM9u6GQD2Md7wR5QI3/QL8
         PrZ9Ll5KHbAyy+6ofJhAlMizB61aZFq8OePdh5reuce8ET/cnl5Umwj5eDJHbj9uNAjG
         KPVm4WAwWgH9QfkXUk8VOBN50TYlbifY7qhi3cVr9oQfQcbWwYBfnNXhXXDHCYEoIqT3
         XrIwg3e/H42NFuPuNxzTHODKGZlG8KHMRcecNLvfwD9kmHHDsbp6aL/gGoGd4z6uYOyV
         vQUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XwmxH0m5;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166457; x=1755771257; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ApgCPfXJ0w1AUCwa+ltrVr0IO8tJ03abLfbEZpAP3So=;
        b=lvcjJIR5fTWEoepZ3xYbr8kibk4Cc9W83jluW2sxMHpfyZlLnHrjNLMdFZW6UCKKxx
         SVOYNXFdQ1YXiR8JvVbDwbLUH4F+sJlI7sC5SZSafho5CuYdnyNatteYEtkmt1itWCpk
         IHPoUl2TVWIMzi0FYCToiD5oAS63Am1c8LT4fWBeFHBJT510WEvCus0DsPyrB1SAlyhI
         29xtduJj3UmJ0wj3Ov5WNoQwUu+8x4taKuJCQcAkATCO1moDiHHXdV/8nB1WjJfmwW6l
         S+KYKjejj+eFDbRCRTFLizTcaAiTXueI6JpgDoDZWokc92Nkd3C+kvIn7lqp1kN53Z8o
         8NmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166457; x=1755771257;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ApgCPfXJ0w1AUCwa+ltrVr0IO8tJ03abLfbEZpAP3So=;
        b=Zxa9q1KsoTwmME6lA311fcQK0IoxKqbfqb+/MljhE49U0asX6waa8TBV0INjK4uIIm
         GgmXAzdyQsTOLURxJGwPh9MyyHaffc/HgKMH1lbyny7IjR9vSHYj4B3Qb02Jv0JAqXyt
         K6Pw0uoL9tTInc04Rwdwg87olu6Fv9UwtpFBoRBoqhmCrfVbN8Ir+0wQKVAtlmZqOFhL
         GpO4ZwvknSb+R/UXs52XAGdLKui6GizaQoa4AKMbrCV4d3xaCLZ1hXOboMhgPKddwfjd
         Hzefp1Y+JASYulPX8hJOWOB6Jr07cDJbROsJ921mS4/Ux/tKqYBmMtEcLcIwOiXdwwPg
         Xufg==
X-Forwarded-Encrypted: i=2; AJvYcCVpYBnktaXJYNI49/w8/snN50sTTa7ljtvtcww00hAgzvkjRA+gFSwoYZo+s1YSNnT6Hnc0VA==@lfdr.de
X-Gm-Message-State: AOJu0YzwOOLzWclxreZOvapLeTf94tchcG+839bLrjNjwSdHPq4XquZ6
	/gmcd9AdXnQecJJ4hdGd6dPY97r0zIUQN63gYCgUxiOZxbFDVrINWz/G
X-Google-Smtp-Source: AGHT+IGieWIZzjpJVaYUOhQuU67n0zEteLCjPcjKgfWoD4SbxL31N590p9QhHnDhOdkWw+rVLTTMlQ==
X-Received: by 2002:a05:6e02:1a8b:b0:3e5:4c7d:b78a with SMTP id e9e14a558f8ab-3e57073fc3fmr44782615ab.4.1755166456647;
        Thu, 14 Aug 2025 03:14:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfrwox+hQ3Q6qrspX9DbBekIdFfoDL+70m6+SQ9zBFF5A==
Received: by 2002:a05:6e02:b44:b0:3e5:1e83:a822 with SMTP id
 e9e14a558f8ab-3e56fbb1275ls7342665ab.2.-pod-prod-07-us; Thu, 14 Aug 2025
 03:14:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUgFu2x65nKIT9vZEjnxy5FNp9SJlohSn9rf4MqaKXulZTxKBOrNfalsVSkCtKUFU8SjQnR4xYtubk=@googlegroups.com
X-Received: by 2002:a05:6e02:1d9c:b0:3e5:5722:2433 with SMTP id e9e14a558f8ab-3e5708ea016mr51136475ab.21.1755166455583;
        Thu, 14 Aug 2025 03:14:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166455; cv=none;
        d=google.com; s=arc-20240605;
        b=RW5DVUt7WFfaYaBomiVZmmAFBOgHc0p4WJ8scxn6kdgC+zuJxhx/EwlBiIag3Om+jo
         F4ebLWZVnWbXRNei2HMMee1F9TZiujMfPBeeiAUBfj3pWwVhzbula75xsOnDk7fz2Jou
         /HlWIb1VfXIXFwCLXu3x9bWfyF7wmopuBC7UIVT64VlG77ga4rW1Q68UJBFUwbVthw6V
         MSD5XEPJoPOClDxPzGwfUASXwxV9DqUuBtdREKuJDbBiSIeAXlKjVEk303XauCZvx/01
         BJu0ZXVkC2kR9Pgg7dgKfhJd8J4R0ILjlS8mcDmgxTMRgIcaeQx91rT4ZUNbjSZJ69Kg
         LzdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XfxLLKvH/DpVc2NbZowrmc3+FoU4H0K6l6sYGFFyH/0=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=Jw/Vv9gwesfbGYNa/HtgYijH3MbinH8g55r15N+RVbrW5tB9GQSvi0zSrE0u+T6fZX
         U17JErCPK/R9I/7OwDi8fb72zdHVJonZnUwk3cfEbXW50QDoedlq6RceFCPGZ9Zzfba5
         zvCwE6UHGKtPwD7DkbS2YBmY/j8V6Uu4YIStWxJJneY3eFvb0Fs2QnCLEqo5YwRkWzSO
         kgtxCmPGbtKqhu8s4ThvjZFLUnfmcUWiDHnhBupKyi/bmKIgbDM0TBjuLv5lhgw3jonI
         7dOOv+R5ipt1nfrZGDL48A18gODibbgNx8NwipMHSHw70Hu1O5RC7O6/eG3SpiIPE30X
         oKdA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XwmxH0m5;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ae99c483esi638329173.2.2025.08.14.03.14.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:14:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 0C41D44BCF;
	Thu, 14 Aug 2025 10:14:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1B5B1C4CEED;
	Thu, 14 Aug 2025 10:14:14 +0000 (UTC)
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
Subject: [PATCH v2 03/16] dma-debug: refactor to use physical addresses for page mapping
Date: Thu, 14 Aug 2025 13:13:21 +0300
Message-ID: <ff3008fd5128ef4221c63716f7e27ff3c63d3350.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XwmxH0m5;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ff3008fd5128ef4221c63716f7e27ff3c63d3350.1755153054.git.leon%40kernel.org.
