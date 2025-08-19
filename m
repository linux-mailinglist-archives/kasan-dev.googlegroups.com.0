Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBYHMSLCQMGQE2DWH37Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 248E0B2CAC7
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:37:39 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-32326779c67sf5265836a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:37:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625057; cv=pass;
        d=google.com; s=arc-20240605;
        b=SGiQ6p+dT7+4GvISyOouG05YCTjeEWYTL0I4IRU/qj0ZOMCHIxoXX2R5mAKOaiFj9p
         0mkdxgUHTy5p/MaMjdnUhaYzFCG+ipQqqaAwbJoDT3ILVVKF715RnhJ6p+cVOUL89My+
         7piBiTdRQzgLqRnas1wGJM7EhXsH8EUGBEldFo54EvQMAWs8BZUoJlfImDq5qUnn3aaa
         6scuT9dlfoy7MeTFLwjrQlNc7GYh8GzUaCpPhn+4R73RBGL+SqDKgDx3hfQkwsR4s1sJ
         osb+S44Z8PNjfBVsTcw8jZtYQO6yqVOZD7pTNEvRgcZBSqHh/qNPOccbFmgSVULthTzv
         dGtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=YyPkAZ1wkhnahrY7hLq0zOZKh651/R4N6T+rdabs8Qk=;
        fh=T6DAxAqVoHU6Vl6CBryglDoINCIp5u88G/6ga7Ty4vA=;
        b=fBqBkXCIMBNifvU1aLT8Yx5R9dUETPEzF835TQAfI8FuZ7AghFX9DzJJA0FGZfbxBy
         ByuVI//XOoWxSNAlQqC4mUjPMgAP1T3g32HwXiMhlDnFx8Im4hG0JoLt1TSL7fljW6YU
         Z2E0lwyJWLuveGEPTHn34Bt2dJ2HvA4AOOCMYUYqPhvm3QuaNUiR7Dt+t5Ii+PjWIIOc
         YXzdVIKRQmGNu6ieEqTt40dwOsq7q77qhjiNpuSYcJgxbsEarhovifzhdk3PWXT0ruTT
         LkSWMRLHsSzg7nQilDYHfXFMl9gKAmrIQevMwvbsi1cbk//V1QROgLLvGkuUDiiVTg6q
         1YXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nRK2iAcw;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625057; x=1756229857; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YyPkAZ1wkhnahrY7hLq0zOZKh651/R4N6T+rdabs8Qk=;
        b=wrRwzXv+rT4Xm6AbEt0xmPT2l2bkhtyJIDfWGpcom8V1BdamjVyaLxw7y1jOKrGBMP
         rljMbMqfjgjDzU85hwtCblWhuxsPxEAGjhin3KvCRuBOJox1U5rNUKD/9m57GEZ1OSOH
         kwDDmTLt0KGRbx2aFsaI5GU31vE7HnejmYQDOMCTsHgy8hgKj3GvJ/fg/30v1u63O0dR
         Qv0b3Vb2/2j8w70XP85UCQ7VegwDel3o0JW5OtTufjm1hVpG+0gnzxI+UtjdZ3Yoy+rI
         VKM3e2alXri/Okbe3HgK76ecdtxd82akW0TJP1vm2HJM0XWFn1hW7yjQsI6PgwDMyNpv
         xU8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625057; x=1756229857;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YyPkAZ1wkhnahrY7hLq0zOZKh651/R4N6T+rdabs8Qk=;
        b=kipiEr9xxcDu/YhEq6GMhYuE+YUu3BeeG5cPjz3307+ODrjsMRMs9imdxGTedouqtS
         LjIMlDJy7eaBsWguF2KE4Pa8dC2CQorYjMJ5L+/6/GK1EVxi27G7uM4gcOoP735JKhUq
         NEV04ULV6fGBYhfGqE6pIhNcNV9PhnEGbqeuN1dbSaeWPSvIgbcDwwf7GQXnDk6WSJ1F
         HqnGN0uBsJNzULB0i1xOKXDmnfXl4oMdd3iGt7+adk+JDAOB0hQG7uh4hiMb7ayICoQ3
         9mZR24yheSKiIZYRxkTyQjlzMhmn+JB33P0z4RtctJSs7F2hSNAHhnrP8LE8jQ0jsxET
         CEsw==
X-Forwarded-Encrypted: i=2; AJvYcCWumM1BFe3GkZd4E1cmu1SXNQKVJQhSJitEMqiorsHx6ZBefxHv6PNAxSKAvdb846BOBTz9ig==@lfdr.de
X-Gm-Message-State: AOJu0YwSXElg/nob5vHyYFpuTTn84OnesvJyHAk3wKzv3BypHMvJc59F
	z8F3LPSMPKhzgY4yn6EJnqczQ9g2bO49fnca/L4FBOeBR9DU3sG3En9X
X-Google-Smtp-Source: AGHT+IEPf+mM+14VK0Vo2h6ecVFsYSTM2q6zwlXmJ5YbkObLYN4mRsZiNA61Je+u5nb0jZT6BpaROw==
X-Received: by 2002:a17:90b:51c4:b0:2fe:85f0:e115 with SMTP id 98e67ed59e1d1-324e1449ed9mr68770a91.26.1755625057193;
        Tue, 19 Aug 2025 10:37:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeovrinrVzkj2ku5HQEzgANLxqR3oV3EC5yR383izWwZg==
Received: by 2002:a17:90a:dc08:b0:313:9f92:9c2e with SMTP id
 98e67ed59e1d1-32326e47da1ls5332301a91.2.-pod-prod-01-us; Tue, 19 Aug 2025
 10:37:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW8bATGjpyiVwFY2LO/POtezn8oXixWD917sdQjF80VzakibRwa3xHPjPakLwePJSYCXYWLIKJxC3g=@googlegroups.com
X-Received: by 2002:a17:90b:562c:b0:313:b1a:3939 with SMTP id 98e67ed59e1d1-324e133bc3cmr112494a91.15.1755625055537;
        Tue, 19 Aug 2025 10:37:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625055; cv=none;
        d=google.com; s=arc-20240605;
        b=DMsnK85kkpxImWYGGxk0a2NzoYbO2gaFXLLkOXrP6e3zVqcCeByg9XwQWi5Ln/j6SI
         xTtv4uw6/3vl3ALLNYKwKA/GHWb3AdVm8iCZZ3d5iAfZTGwpMt9xjcKaSf8iUbqUjcEk
         DaxwMshrW9wsJWyyRni4N1xQ9QDztgXpWEuEfEi7SJnjkdHWxXFdhnk6BU6H9bt9Um5q
         AgTDVoLZHARqUNb/PduVtYsQrR/4H2J7iTf5D8XTUqqhtI8dym0T4ACKG/clkjfj8T2/
         e8hB2GELncnm45gVJWtbMr0qn8o6EHlOOoThWk7tV//iNA3Hiingel463ROuW2lQzsI1
         OoNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XfxLLKvH/DpVc2NbZowrmc3+FoU4H0K6l6sYGFFyH/0=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=jKf/ImiSXv9aL8BJLhnZX2VIQF78xsHT6ucMvlxpqjwhFtFxWPU+fkX8I9Dh67vQ9d
         HM5bACt2rRYyX1e74FSxtiNWlu8P0u2vZID2TV7nCACXaxlwmXdVDABo4mbMYo9IZi+r
         af3oBpycBbIa0Z/RwLCDv0CgGIVyO5dsw47U7BP+0Zc/B/lMPNuaPtoFjerl+LbJIE2z
         IEI2zR+7qKMrfRCWI5AY1Bo+GIhArtF4PFDrPXt4tpU5J15oYgjdA10DDloJXpnCeCOh
         KRPV9DE6MTHj47SE95rptHlwTxoK/tr2rHnquGlfDVrmhyvXGqBureC2pmkywZVfMQTz
         K2yA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nRK2iAcw;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-324d318fd39si112892a91.1.2025.08.19.10.37.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:37:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A6B125C647F;
	Tue, 19 Aug 2025 17:37:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1EBFAC4CEF4;
	Tue, 19 Aug 2025 17:37:33 +0000 (UTC)
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
Subject: [PATCH v4 03/16] dma-debug: refactor to use physical addresses for page mapping
Date: Tue, 19 Aug 2025 20:36:47 +0300
Message-ID: <478d5b7135008b3c82f100faa9d3830839fc6562.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nRK2iAcw;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/478d5b7135008b3c82f100faa9d3830839fc6562.1755624249.git.leon%40kernel.org.
