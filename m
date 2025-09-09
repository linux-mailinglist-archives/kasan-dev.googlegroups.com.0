Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB6WWQDDAMGQEIIAS7MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id F14F5B4FCC6
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:28:27 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-6217104c290sf5602213eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:28:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424506; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xn5jXn5VP8Q7UbyhfzWshWTopVoWPslj6W5Stpf5606NUiZCw9jEcHFXz3EiGkhoV2
         BtNt/kW9wleW9UuYNORWRus0TY09dgaElVS5168ZQv0vR+g6MJCsroCZvsXCbKn+1PDX
         zoTd8Ovk+qcX+479lwsyXIt9JpRsj77hsy+nbjEPBgHCtkbM/gZtE2TU+LAsI0ODZUcQ
         ZXtW1R2jRPExq0/uCR18CW6fqqQh1wyoWhxywYzUJFj7Os+OG2LjrCajVEn8rdmyfuaZ
         hD9uWa3zwQJ6dP4yvgoJGmoQyD2SHHk6NqHMwLytWVY1eMXdauEuJ8hn38H1FGyLk7XS
         NlEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=4Dz6sAtZnG1mWkvnzv/8ApyiSLUqKJJMOKQoADWc6RE=;
        fh=/FTTbtRdyoDW3glxZ3x3G4JwKTF729ChmAtOm4fiYgU=;
        b=OT2kR6mGLySqn9C6XH7WaW3//UrKqwx28KHo7wUqVhbrv4/xbp2/MRbaJPLxUFgROb
         2SLqtHO1XFQgCaE+Xl/hY8PfkPDTqUo7VWLhRB55T6ebrBYO4h18a+uIdihIBTugGDZ9
         Pojj6CGdfO3HKN8Bxzr6HoGGd9qTDYAXBtKqpvyygp16R+r8ROhxPlbYxhfcIIPGYwTi
         f/SobX4cbXbUuunl1ghq1ujGOhdmsnYc1R7AqaVoeH7T6DayfuAFuNyqsHi4bFvmmeq8
         tQNySvFyWJp/A+TKkmaPvPwnmuSU1mXStiFyNGbXNN14o3ZsoBU5JfmVgF+X+91h+b8e
         jx9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ke4hsb0o;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424506; x=1758029306; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4Dz6sAtZnG1mWkvnzv/8ApyiSLUqKJJMOKQoADWc6RE=;
        b=rLzQ24VL9FUcFR+PwKOx4VUKhmSLewPxP3C7Z8xY9KzGmqtyjh9pyN098neT7mJmkC
         Fg4h20hadLt1lez/Yv0X6QRGNLwdZvEg6p2xUq9E0lbOi5M2HsSK2lnmX4jCTul88NkI
         If34HW4smU9a9hoaDUwDXHakWpRorVHJFdM4yAZfZmqCGMFhVKolzqPFLVGOcgp4xh+/
         Kczx1c3QURUyy8MdVpsfKVwaOUkI5ACINE6+/71KVQ1yjy6JChALg20WKqIjYTKu32f5
         OTCnex61KORsv502GZdtMAmhggNOajiBMMZvlW0x25PQ90pf0WhU5wWYe+538GRBkJFA
         KYnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424506; x=1758029306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4Dz6sAtZnG1mWkvnzv/8ApyiSLUqKJJMOKQoADWc6RE=;
        b=HlgM/9BA2Sp+c+tQNTZtsp/pJha7UD2QUL3U6YxGgPqAz9/BXgVgaw/j6LTQDJngs3
         rTKG6V3fYkgw2v9lGiZ/9MCj2yPQg2mJra51pDEt/swFWTxHz+pxApQXWLkkPzhjNKMp
         sz7Dr4k2bW88ED6MXVXNC3Cv3bIyloeQyWyW7NL2yFJ3IRonR1Dze5zpkqr/hGtDYPEV
         JfrxrNdqNhcH8MDPNPIXREaZNL/kJflasQZw+Vy5NOhEW7GqM7TNmOwjuckYdcgDrW/H
         j02cNnYIGhFn5NeBTp73k4VZiTr3Osglx6nVtraWfRqZfFmpwfAQHPamAfn8rBzFlxc/
         qMDw==
X-Forwarded-Encrypted: i=2; AJvYcCWY1BzFCQCiFFOoCLBuRPZab2jKj9uGUU9PoukotLB42tEbZYKqgESKslCYtzPDiyPbpnB1Og==@lfdr.de
X-Gm-Message-State: AOJu0YwobnX/SEbjgoM57SfVhyK+k1HCnhndZQwR/kIBE91TuWoqad/k
	CYmtXpIfjv4xVCLeGHCWwTfxwb0qYWA9QVrUq4xBkzZoz4+6N538qoyM
X-Google-Smtp-Source: AGHT+IGwMBza3xdvv3zzSq2Me3jv5eE6hKiLyxtLVj4MhCD3pXqSl/jVx0K2nf+VZLBwhPt0bF4HOQ==
X-Received: by 2002:a05:6820:826:b0:61e:7139:b476 with SMTP id 006d021491bc7-62178a0ee14mr5165121eaf.1.1757424506382;
        Tue, 09 Sep 2025 06:28:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcg8B/vK1ix7I8PBvGaDHQ6QjNqjgVubZ8iqE5beic3Eg==
Received: by 2002:a05:6820:4602:b0:61d:f8d4:b321 with SMTP id
 006d021491bc7-6202592fb31ls1335689eaf.1.-pod-prod-01-us; Tue, 09 Sep 2025
 06:28:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWra3x0gv0+eV9zL76ZmfHjqOgNOENh/Scna4XRjsm+G+fdwdaQsrQSzjCh0oeXi+d4ol1du1mSTvs=@googlegroups.com
X-Received: by 2002:a05:6830:490a:b0:745:a41d:22b7 with SMTP id 46e09a7af769-74c7851b7d4mr6173851a34.27.1757424505112;
        Tue, 09 Sep 2025 06:28:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424505; cv=none;
        d=google.com; s=arc-20240605;
        b=a7dPGX7uv1MCgwFioN0ThDXTyUAR3AAtIo8879KNdRur0FVrHle1xEUwwptwmyzh8V
         pthXE/zIK9SNDKYf0Inxrx1fxQgv6deK6zPe1yLdKSeohb7VwdZdZi0DARxxZhtzAZB5
         ybXX4SfyXWGNc1iYw5SQKTJwxgG1Hb9bBgCRbEtf5wE10YKl3Ao3vglM77tnQw0NKv80
         l8jDEOy1dmxpZ8gpQCTwnqAKRxMw588apyVsOY1hOJhj54Dpr8NM0o2172ztYthTVB+r
         5m5RVXLyO+a5colHqI8FuJtg6rzSQ5XV5zPq03s7z84YwWiSWzQhPlMgR2+ZTcWZ7y3D
         /kSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8iG7pwhsLyN1oJdsR+XgmnjA/Fm8L+gfJ9NBOwj+hF4=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=ksRoK32w28YHas/N3gvS1iimDVa6cKcGCHyDJp3dylEGhgsqscdFsSDe/h0emPNSRJ
         OhbTu8CAKCxTV69LmVN5quzNQMP6XQiZ1D6Ea7llwprzrPYyvVvLiK83ov9iNRHGBkIL
         GfLiKmaIrFhSWaIIizXw9jx+5D3TE3KDt3YGxptv440BouZ8cP61qkofe4rQ17L1sqKH
         EYv5ZWwi8h/xuFiHV7D0/eVnMKC4zjMaanDUe3gFA2Xmu5bNBLaLbbFTYYg5dh0yEYF5
         8xy7FlcDMXh5F3K0iv/MB68nQy79BBFXSe+b5EDPVnXdWHLvLUDyppad5AEp425aoH2r
         KnWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ke4hsb0o;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-745a33b347asi610860a34.3.2025.09.09.06.28.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:28:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 2600A6021E;
	Tue,  9 Sep 2025 13:28:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1DD48C4CEF4;
	Tue,  9 Sep 2025 13:28:23 +0000 (UTC)
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
Subject: [PATCH v6 03/16] dma-debug: refactor to use physical addresses for page mapping
Date: Tue,  9 Sep 2025 16:27:31 +0300
Message-ID: <56d1a6769b68dfcbf8b26a75a7329aeb8e3c3b6a.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ke4hsb0o;       spf=pass
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
 Documentation/core-api/dma-api.rst |  4 +--
 include/linux/page-flags.h         |  1 +
 kernel/dma/debug.c                 | 39 +++++++++++++++---------------
 kernel/dma/debug.h                 | 16 ++++++------
 kernel/dma/mapping.c               | 10 ++++----
 5 files changed, 35 insertions(+), 35 deletions(-)

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
diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
index 8d3fa3a91ce47..dfbc4ba86bba2 100644
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
index b82399437db03..b275db9ca6a03 100644
--- a/kernel/dma/debug.c
+++ b/kernel/dma/debug.c
@@ -40,6 +40,7 @@ enum {
 	dma_debug_coherent,
 	dma_debug_resource,
 	dma_debug_noncoherent,
+	dma_debug_phy,
 };
 
 enum map_err_types {
@@ -143,6 +144,7 @@ static const char *type2name[] = {
 	[dma_debug_coherent] = "coherent",
 	[dma_debug_resource] = "resource",
 	[dma_debug_noncoherent] = "noncoherent",
+	[dma_debug_phy] = "phy",
 };
 
 static const char *dir2name[] = {
@@ -1054,17 +1056,16 @@ static void check_unmap(struct dma_debug_entry *ref)
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
@@ -1072,10 +1073,12 @@ static void check_for_stack(struct device *dev,
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
@@ -1204,9 +1207,8 @@ void debug_dma_map_single(struct device *dev, const void *addr,
 }
 EXPORT_SYMBOL(debug_dma_map_single);
 
-void debug_dma_map_page(struct device *dev, struct page *page, size_t offset,
-			size_t size, int direction, dma_addr_t dma_addr,
-			unsigned long attrs)
+void debug_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		int direction, dma_addr_t dma_addr, unsigned long attrs)
 {
 	struct dma_debug_entry *entry;
 
@@ -1221,19 +1223,18 @@ void debug_dma_map_page(struct device *dev, struct page *page, size_t offset,
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
+		check_for_stack(dev, phys);
 
-	if (!PageHighMem(page)) {
-		void *addr = page_address(page) + offset;
-
-		check_for_illegal_area(dev, addr, size);
+		if (!PhysHighMem(phys))
+			check_for_illegal_area(dev, phys_to_virt(phys), size);
 	}
 
 	add_dma_entry(entry, attrs);
@@ -1277,11 +1278,11 @@ void debug_dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
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
@@ -1305,7 +1306,7 @@ void debug_dma_map_sg(struct device *dev, struct scatterlist *sg,
 		return;
 
 	for_each_sg(sg, s, nents, i) {
-		check_for_stack(dev, sg_page(s), s->offset);
+		check_for_stack(dev, sg_phys(s));
 		if (!PageHighMem(sg_page(s)))
 			check_for_illegal_area(dev, sg_virt(s), s->length);
 	}
diff --git a/kernel/dma/debug.h b/kernel/dma/debug.h
index 48757ca13f314..bedae973e725d 100644
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
@@ -62,14 +61,13 @@ extern void debug_dma_free_pages(struct device *dev, struct page *page,
 				 size_t size, int direction,
 				 dma_addr_t dma_addr);
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
index 56de28a3b1799..0b7e16c69bf18 100644
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
 
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/56d1a6769b68dfcbf8b26a75a7329aeb8e3c3b6a.1757423202.git.leonro%40nvidia.com.
