Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB6MH3TCQMGQEUSL7HHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 631FBB4079A
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:49:31 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-24b0e137484sf8745935ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:49:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824570; cv=pass;
        d=google.com; s=arc-20240605;
        b=hKFMmhNyd70TeITSORLrDK+u8B1Th4DhpDdBhhHpjm6oRHjaVrotr3RggZ5GOu8ZX7
         anboMLRoQUvywpg7JTIvySZx3ySO2AJqdWIw2l/H2qU7kF7cnTB/TzkkPhu/ys3zEvkR
         VxVqngggKpKKsrlUXzaY+o4I2Mhx0MUx+7FfpO5pRfcSZFzy22+jhsSu9BdvgxfyrB84
         lSFO8zQGudPB8zAM4fugbhPPqIcS7AW1PsRlynWD9IGzqiMXTTz/OcAv1qbFKkRQt5XN
         MQY/0SpyJYVtY+ii3dmihw9inra8d9ElmfPsr/EkHD0nTG5vEG5RVuGMpC9E4yDLEX9O
         y9qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=d0+MHb4VAcYk9cRSw7vZOIvroYgPD2mnMepHAq5/584=;
        fh=GicLmxWCEbRK/VZr5LZXZzr6ijTLXWpcBs9duXSdSUc=;
        b=fXT6Pj1W712wuuTgRnyqVEK3mRB1I+KNgf4JzKMS0HpmkmLAByf+bMIVmxQXfk/mXK
         0B3/2epxTbPj0ZPHbZhICtmq3pimFztiUyj+zzTuv47KroGeb5Zfcd83ZlwVBktM3ZvF
         m+t5g0MSYT0d5gViTMiblitCMrz0qCae1heNDSfshk6+2LfSm1DAVHF6lTmt6orE1jyx
         ZTySGfKBOpfpK5RoXCvEjNdGxaTxaKR0e6DAz279H4AKwvt4n4N/V83KwqgP5XWnkV3M
         5x7BCYQ5x3pmWYwovHNeDyf+2PqIDDNUh7JYFYXbkTZfG2ErWXX4VAjWwCsbmKm5CDWN
         Do4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i1626xjV;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824570; x=1757429370; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=d0+MHb4VAcYk9cRSw7vZOIvroYgPD2mnMepHAq5/584=;
        b=r9QOZYU0Rf4Iuoqc497A4pFJa1yQ4K4LwCb+EjEW9/5Qb++o0aiq9o69n+QQBacPO4
         1XXdUQKzO4Ds3KYz55p6Nm54ugsMpTEnkd9YKQnXAdtC9yZXq18ciluZtCVuGFh7JD2z
         p/YKbAlMlB5HPmbYqt7RwoPusyiRmGLF8qKSCLVa9HKlmAfSon+QpVUVE1f7xQEFGizy
         DTn5KXJlFyQ7VWk0kBAS4ONYIP6J7YtrlFa6taj5wx/TNq0D8Ul6Sa7+Bj2AkjxkW14D
         a8ary6S3GvcR1hHNIZvSR3sWcIpWZ97y0T/6Nk8WOw4D0fVOKMyhp+SaO4dpDQJEqOUD
         V1YA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824570; x=1757429370;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=d0+MHb4VAcYk9cRSw7vZOIvroYgPD2mnMepHAq5/584=;
        b=xMqT16CeyLJWbCQBIODN/w65z8K+XJqVq+TYUpjVBSQ0dBSr4ArHwnsPAJo//x0Bh+
         CPUkmtjlgE5xH6p6KrfrM6nptO0vXEXRwWHKU91kv6AMSFNrC/dTuZDo9o9jqfeWbzG3
         rPhm+owjd6ZvhgDmPPfInARJswQxwJzNzIxfJO3J5qt6omKaSQ2jsf+ICp6mS3fhHTEL
         8YTLolUQUQvCMOsWE8BKPubxmaDCEq7MRXXSd3zFPOFNYfPASQHVf1NeQ2YS201ripza
         YEQbOzwSmtSHpmGYqiAkAtS5QoxqGWl7ViSI/gTokEvR8/iHbE1JYkIhd+rROTDR5r2v
         2hVw==
X-Forwarded-Encrypted: i=2; AJvYcCWOb/5CCEWTbj3WL6l5E816D6tVPqHK6J1OFhck2UR1sYkunuyMJ+ooyaE9Q0tWU8g+Q0IdFA==@lfdr.de
X-Gm-Message-State: AOJu0Yy8S4fVNBJzqueL2FKBO2LzdlHr+n8rmH5xygMpqiVF8m8DA0ja
	2cZkeEm5t9e/O7hSawDW3fVJW1VrDkVaKphYSULmuxL+HjR5QhFHoDhk
X-Google-Smtp-Source: AGHT+IEHRWPAuKTaR3c8wJV2gyDowtMhr/G1ye3PhZ+qeO5IdxQa9azsRQnB0224jg9L57Za1QouPw==
X-Received: by 2002:a17:903:41d1:b0:249:1f2f:82b1 with SMTP id d9443c01a7336-24944a987a3mr162993965ad.36.1756824569932;
        Tue, 02 Sep 2025 07:49:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfIrq1bIOa9qwtBadrlL9BHjb5Kekxv9QN0uVe7k6l26Q==
Received: by 2002:a17:90b:4a03:b0:327:e760:af15 with SMTP id
 98e67ed59e1d1-327e760b035ls4020501a91.0.-pod-prod-04-us; Tue, 02 Sep 2025
 07:49:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVXnwjz/g0bjpQRZRnWETJ6SuvIzhLj53npYtF6BEm794P0EBm7z7T/NbUNwJFZh48XIHS4AYtog20=@googlegroups.com
X-Received: by 2002:a17:90b:3fc3:b0:325:1548:f0f with SMTP id 98e67ed59e1d1-32815452baamr14864036a91.14.1756824568444;
        Tue, 02 Sep 2025 07:49:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824568; cv=none;
        d=google.com; s=arc-20240605;
        b=i+NoOEeyfFISVEhqL9eL9TKSLUPYETVORC22Q150RzMJ62lhDX9weUv4wxiVfaLxFh
         dDTPa9GbyN+4Dl17aoSqB1geLcEM8vcH8/7PhfrdAuHh8emqYnD/mei0y/Etco3OOFB5
         oKY3yzn1afuRmsHvZC4Nh+HfLE/3jKK1Z3CYrxSRN0Cfc6lkHFL2SOA9ODK9oUZ0OHsg
         xJXIR3h/OcvIOJkDjD7UamjolcODidAdfI6EJgDkFKRlBCX8Q+YvV+9FXmBFilKpVbXj
         r66x5i8GLLawmuQZFDmrZVRubXgY2OqpxNms2yImZOSoKEovse+G0fTpe8merW6IJ5wp
         78EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=c3g1lMNzmhoxt7IeBcgSIV29OAcSm7jebsMcZqg087g=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=BRapduMF9NFuUL5oANArYxZSTh9vO2LN3j3plivb+zY95xfbXS13yMAn7VluDDZg+K
         UwkF4kX83bYWLkO6F4EMIN9CaxUDUCCt5T03tVyMeAN/nV62KtWQGEQphmjhMF7CanGi
         b7ZQRltsLwfKXFPouE126vkJWZ1XmTOTQJsC1voa3QnaJqPZ2y8C4T07FToQLaK37D9y
         PmwG+ue5K8mVarjkOrmyYT5cOwHcOJwY2M1uwZ8OM53dwaZFVpw5472v6XrBT9e4fAS4
         KJ2BN/ZDtBFaypL8C9S+cw3J2y3lIK2cL9WyHIIcoJ24YNq9fXFdn0o3i423Nsbpgy5j
         Nc3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i1626xjV;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327d9331daesi539442a91.1.2025.09.02.07.49.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:49:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 7F0616021C;
	Tue,  2 Sep 2025 14:49:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 61C06C4CEED;
	Tue,  2 Sep 2025 14:49:26 +0000 (UTC)
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
Subject: [PATCH v5 03/16] dma-debug: refactor to use physical addresses for page mapping
Date: Tue,  2 Sep 2025 17:48:40 +0300
Message-ID: <ae1df479d6d99ef9053b2772f3da3bf0524491ac.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=i1626xjV;       spf=pass
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
 include/linux/page-flags.h         |  1 +
 kernel/dma/debug.c                 | 38 +++++++++++++++++-------------
 kernel/dma/debug.h                 | 16 ++++++-------
 kernel/dma/mapping.c               | 15 ++++++------
 5 files changed, 39 insertions(+), 35 deletions(-)

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
diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
index 8d3fa3a91ce4..dfbc4ba86bba 100644
--- a/include/linux/page-flags.h
+++ b/include/linux/page-flags.h
@@ -614,6 +614,7 @@ FOLIO_FLAG(dropbehind, FOLIO_HEAD_PAGE)
  * available at this point.
  */
 #define PageHighMem(__p) is_highmem_idx(page_zonenum(__p))
+#define PhysHighMem(__p) (PageHighMem(phys_to_page(__p)))
 #define folio_test_highmem(__f)	is_highmem_idx(folio_zonenum(__f))
 #else
 PAGEFLAG_FALSE(HighMem, highmem)
diff --git a/kernel/dma/debug.c b/kernel/dma/debug.c
index e43c6de2bce4..a0b135455119 100644
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
@@ -1051,17 +1053,16 @@ static void check_unmap(struct dma_debug_entry *ref)
 	dma_entry_free(entry);
 }
 
-static void check_for_stack(struct device *dev,
-			    struct page *page, size_t offset)
+static void check_for_stack(struct device *dev, phys_addr_t phys)
 {
 	void *addr;
 	struct vm_struct *stack_vm_area = task_stack_vm_area(current);
 
 	if (!stack_vm_area) {
 		/* Stack is direct-mapped. */
-		if (PageHighMem(page))
+		if (PhysHighMem(phys))
 			return;
-		addr = page_address(page) + offset;
+		addr = phys_to_virt(phys);
 		if (object_is_on_stack(addr))
 			err_printk(dev, NULL, "device driver maps memory from stack [addr=%p]\n", addr);
 	} else {
@@ -1069,10 +1070,12 @@ static void check_for_stack(struct device *dev,
 		int i;
 
 		for (i = 0; i < stack_vm_area->nr_pages; i++) {
-			if (page != stack_vm_area->pages[i])
+			if (__phys_to_pfn(phys) !=
+			    page_to_pfn(stack_vm_area->pages[i]))
 				continue;
 
-			addr = (u8 *)current->stack + i * PAGE_SIZE + offset;
+			addr = (u8 *)current->stack + i * PAGE_SIZE +
+			       (phys % PAGE_SIZE);
 			err_printk(dev, NULL, "device driver maps memory from stack [probable addr=%p]\n", addr);
 			break;
 		}
@@ -1201,9 +1204,8 @@ void debug_dma_map_single(struct device *dev, const void *addr,
 }
 EXPORT_SYMBOL(debug_dma_map_single);
 
-void debug_dma_map_page(struct device *dev, struct page *page, size_t offset,
-			size_t size, int direction, dma_addr_t dma_addr,
-			unsigned long attrs)
+void debug_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		int direction, dma_addr_t dma_addr, unsigned long attrs)
 {
 	struct dma_debug_entry *entry;
 
@@ -1218,19 +1220,21 @@ void debug_dma_map_page(struct device *dev, struct page *page, size_t offset,
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
+		check_for_stack(dev, phys);
 
-		check_for_illegal_area(dev, addr, size);
+		if (!PhysHighMem(phys))
+			check_for_illegal_area(dev, phys_to_virt(phys), size);
 	}
 
 	add_dma_entry(entry, attrs);
@@ -1274,11 +1278,11 @@ void debug_dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ae1df479d6d99ef9053b2772f3da3bf0524491ac.1756822782.git.leon%40kernel.org.
