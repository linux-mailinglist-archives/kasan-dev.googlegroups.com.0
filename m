Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBXXO57BAMGQEDD2NGTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DEABAE8440
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 15:19:31 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-74ad608d60asf721812b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 06:19:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750857567; cv=pass;
        d=google.com; s=arc-20240605;
        b=kjjnSciCR23zoPqDJuZgDwL9MYfNUZGZ460YhM07gqCPcVUmlaNsYHOWZxe6kY7T2l
         ezz8G4hUv51Mo0x3/VWf5zwm+rWMxvxTK2qaZo6InURJJeziWmbtTUjzWj8bTa5nmjAd
         QYAmCuAKe4vFZmHJVXLDZIBoU8Vk60wc1sXXKX3un9HMx3wwti7Ami8VbRxvMMnW2d0v
         yGwj3VKna0STuicSn2YZDMu7hxhFTQWNCfq0luHe7O9za16Dh7Ci1OywxWUi4fkudftk
         n9q4/C3NL7QfP6Fhe58THvkli0s7y60pRs54y10Zah9/jcVJgnfcrL160Jf5BPxqOjmZ
         LuUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=YAjHAnmAJCUo+gOy2PCt7YeVakDm3A82i5VvWVsVbFY=;
        fh=7gFWKIwpVV2rJPgQicHCJrlNPe/Jk44YmTlo0xG1xfw=;
        b=OOe+O/hTKG5wFLWgCh54N7uJgNg57QKvLF8zmPS70kY8bXYniFzW5ngsHhqWHmCoIM
         2Vu+n1kXpDA3KAdmSRcWrkduw08pbKqcNizs8a8IO/WIash4fChn/ougNwwOfrDgrF+Z
         f3AbtBPgw1kHP6HUanV0WcIR3oCCuILZBbHcif2DcmO/IDCrfG4GXXhQIBbfwWc1VCFi
         rA1VOmm+NrJcJ2MQNBW2rWSPzqA+287QQvWDGYY6ai7tn1NNiFxIz0gz4NbXpzce5LsK
         7faoDBcJTrPJDVkoh4QHc3b79zIsvLqFVVWwICrwenPhzExXHvjjOGj4qaSZ618G0weR
         50lg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OtDreryU;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750857567; x=1751462367; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YAjHAnmAJCUo+gOy2PCt7YeVakDm3A82i5VvWVsVbFY=;
        b=bHAKSC4nG5JqHJbK+flSGCDdoaJhr04cmvR+ciLV3NiB/HWHB7+n5A1TFJF1QM3Pzk
         sn7hEES4iSafDloRsMrjMix9WNOHYkHDswjaDG6Q8pcLrUf3PaFo8toAVd3brf2OQzlH
         zevwnDyxRtSNW30p1AW/ntVnFVTdANtr4fg2apuefIgDmzkbNXnXWyevWFZqiZvCtEyF
         HrqxXzRXYhA74N3qv4K8ZtZrTO5/WzsNTKGKLsX9YU8PAwlZFzJMdGox3KoO1oNHNKbd
         u595i7TIoM9Flc2MKYs6zCeDVjyWfHgK+wfrgJ+OPxjWS+buWUWmIfm+xGAoVb/seq4X
         Bgxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750857567; x=1751462367;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YAjHAnmAJCUo+gOy2PCt7YeVakDm3A82i5VvWVsVbFY=;
        b=atvUp0knkk5j2xeVGZmmz+8zfQVsj+XF//swI0zwrhsJNM0TD+O/TsHOUjnrjHYM/v
         YAxYN0Su+w64aOoncIQHZpMMSIGRyyjy0/RTtqLAyrYoECJREKEbGvdhM8dPRCT52vbJ
         2cbT/kWOC2ergwlW6Nn227bZ+eh6RIQMIIDfceiNOFvhLf1oedeaB8iR7wi0OaV7xeRW
         Tvv4fImGq0AkpISpNGg/QYU2t9s3WVNgVgwqwH9RAnpt4q9e+Z0h/+/mjzzlQ/CQ3Ycu
         uwhFcL6F7WfC83LeDQlcN77f7QFHGaTGqQYqnrkruKW9nIyhaB/j+SkEDCqgMQw5AptC
         pCDg==
X-Forwarded-Encrypted: i=2; AJvYcCWOjBM4ryyuahXuaV7NVLdyfn8Utmli+KyOPjwxG5y10HH067aB6BzYR5xeCDNvOmALRTFYVg==@lfdr.de
X-Gm-Message-State: AOJu0Yxwqzl+o0u5Ij+TmD5HfPr2zWLLlbHZ/vlkHpHJ+HAd+5wa6Vgs
	EjTMsv3QhNh9QkDJeVZHiSkXl3eWoGloGCyZa0dAWjJSgnrAMmR1M2GJ
X-Google-Smtp-Source: AGHT+IE1YeZit4JwEJX0ihYXEwcBUbORIVQbuo7w4J8hnDwlNNUkOTx/K+uroQtSRZ6QYjugOlGldw==
X-Received: by 2002:a05:6a00:4fcb:b0:72d:3b2e:fef9 with SMTP id d2e1a72fcca58-74ad45b8003mr4747372b3a.20.1750857566589;
        Wed, 25 Jun 2025 06:19:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe6oXiSqrpJkcZvdjNLsxmN125pWXADBim/KSwC//aNyg==
Received: by 2002:a05:6a00:84a:b0:742:c6df:df1d with SMTP id
 d2e1a72fcca58-748f96c6336ls7765213b3a.2.-pod-prod-05-us; Wed, 25 Jun 2025
 06:19:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXp/Aao9KTrfRRMU8lC26Rz5hfkRJccGWN4v8ertjn6IBryyRCJQpCOd/cs771S8jMXrSSroXX9A6A=@googlegroups.com
X-Received: by 2002:a17:902:d487:b0:234:986c:66e0 with SMTP id d9443c01a7336-23823f65e77mr56306385ad.4.1750857564940;
        Wed, 25 Jun 2025 06:19:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750857564; cv=none;
        d=google.com; s=arc-20240605;
        b=XOi9hYcPIfu9rZ+D5OIYacnBnu4tnfIQ9o7+t18oQZniicAXjomNocrlzafJfESbUc
         3i09jGShZrbe93SaweVKecEo5XsgsrKQ8YWTz1p4nczXBQCpLszON1n4KVg3sUzf2ggO
         JsJU8/3F1D08fySdVVPNLtNMe1kyo1RyNorPlarVYGxXm7EBxINZt0xZOLu89lMGKMgH
         adPYawtJcnMv+L/0HGoJ8vfhcIa7mtnIvr9oUrZeqdzlGooJbfyyJ28SJeJVbJC0GmY+
         XTOS68M5RFGe6nWfW1Gm9A/R9A5P7YoAbbRbaZGT/39ybAWCrU9Ykrsm2N8jqQS65E/m
         v2Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ko9vZgGLl+t6FuSeE22rsHvlrBX1nVq9FWcYg9wkspE=;
        fh=Ue3Mp6STgOoLoEGJ5Njvvyw4rTb/NHl4sWIWt9sNi3o=;
        b=hj/ppgwmpX2jwqJnY/kHgUZNOJ8xSnOpj0Ld5IZuA7UGoouvGoyzXY77lIwlG31GGs
         GbsIUAFFSJw1WMBqHAoaeOz3irLJlLF+Fr1xCREXIT9SkATP1dQdkpnyCZk4g39p2Y/P
         UUqj075LBFOdVUNzRfBzpx5J4DpK6b4zGzpvgpJQzGgyPn2uO3aV2agP3nbgEcZFfarq
         7lTr8VgItJYyK4EcMPtlQCZXt0zoXJl4ANN04JPFgbVva9bRcnh5zT1JhqDQDP/ygzfd
         B61kf4MfGTt0lyMuggX+qt5q3v/CsFlTx6gom57Nw7HbXE7kmYsG8OpsDlj3AUjaipVO
         3AXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OtDreryU;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23809dc45c7si1443845ad.2.2025.06.25.06.19.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 06:19:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D78325C2691;
	Wed, 25 Jun 2025 13:17:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E310EC4CEEA;
	Wed, 25 Jun 2025 13:19:22 +0000 (UTC)
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leonro@nvidia.com>,
	Christoph Hellwig <hch@lst.de>,
	Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Robin Murphy <robin.murphy@arm.com>,
	Joerg Roedel <joro@8bytes.org>,
	Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	=?UTF-8?q?Eugenio=20P=C3=A9rez?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?UTF-8?q?J=C3=A9r=C3=B4me=20Glisse?= <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	iommu@lists.linux.dev,
	virtualization@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: [PATCH 1/8] dma-debug: refactor to use physical addresses for page mapping
Date: Wed, 25 Jun 2025 16:18:58 +0300
Message-ID: <0390f8a813002e27d41bfb9c33041e699ffedf05.1750854543.git.leon@kernel.org>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1750854543.git.leon@kernel.org>
References: <cover.1750854543.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OtDreryU;       spf=pass
 (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
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
index 2ad08517e626..7491ee85ab25 100644
--- a/Documentation/core-api/dma-api.rst
+++ b/Documentation/core-api/dma-api.rst
@@ -816,7 +816,7 @@ example warning message may look like this::
 	[<ffffffff80235177>] find_busiest_group+0x207/0x8a0
 	[<ffffffff8064784f>] _spin_lock_irqsave+0x1f/0x50
 	[<ffffffff803c7ea3>] check_unmap+0x203/0x490
-	[<ffffffff803c8259>] debug_dma_unmap_page+0x49/0x50
+	[<ffffffff803c8259>] debug_dma_unmap_phys+0x49/0x50
 	[<ffffffff80485f26>] nv_tx_done_optimized+0xc6/0x2c0
 	[<ffffffff80486c13>] nv_nic_irq_optimized+0x73/0x2b0
 	[<ffffffff8026df84>] handle_IRQ_event+0x34/0x70
@@ -910,7 +910,7 @@ that a driver may be leaking mappings.
 dma-debug interface debug_dma_mapping_error() to debug drivers that fail
 to check DMA mapping errors on addresses returned by dma_map_single() and
 dma_map_page() interfaces. This interface clears a flag set by
-debug_dma_map_page() to indicate that dma_mapping_error() has been called by
+debug_dma_map_phys() to indicate that dma_mapping_error() has been called by
 the driver. When driver does unmap, debug_dma_unmap() checks the flag and if
 this flag is still set, prints warning message that includes call trace that
 leads up to the unmap. This interface can be called from dma_mapping_error()
diff --git a/kernel/dma/debug.c b/kernel/dma/debug.c
index e43c6de2bce4..517dc58329e0 100644
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
+	if (pfn_valid(PHYS_PFN(phys))) {
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
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0390f8a813002e27d41bfb9c33041e699ffedf05.1750854543.git.leon%40kernel.org.
