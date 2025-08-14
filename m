Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB7HN63CAMGQE4WBOKPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 338A4B26201
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:14:22 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-70a88dd1408sf17647676d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:14:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166461; cv=pass;
        d=google.com; s=arc-20240605;
        b=KJVz+gBWgsrvahnoC2Im1dJkecx3486Fl6jhoNYSlE4SKUGGi9KNwe9FAs2hLOSeIP
         yP9MVbJMdUqZzFm5vokYRInuOK6n3dUBk1bXiXrPjaCDcBM9kpzJ3uuH/4NFGwAvabL0
         ZuRUWiUQbe96ul14kyImfjLCGdiflgAmfxV6fDi38ClZNVSi6isN78DBTa4Z/ritxMk9
         9oV8yXsaZuYuj5TzEISANMB48ZKZJLfqJ8MikkhvgAEdKL0t3uR+rCZYNmJq509znAht
         fTYRCHSDl5GU90AXpyxZJEkGjC9UfuUPf2Punbdc4USFGlJuOjI39C9jkCyJTnFGwytG
         IXzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Dc1++BVJOIJjEDfSmxfPCfbfvz4+11WWHMbAMG7BUXc=;
        fh=ECpEGkIKfIxhlpBLKWNhe/ypnpITdfXUcaKerDB/iYs=;
        b=SbiJRmOGDRr0Pd7ALoFezIjvjCpAGE46XbuSdDDLmafk3vrof8EDJPmNWvE+VaVCAR
         LQXqe/Yd3uAXnfBLDU/oluzTsi0lYc5wGOczU5qgagVelmwWal7FJ3E4mTU6ixTVr9/Q
         7uXfkD+BzXOWAHYVI767uwK2QKYTJlZwwon+oecY6TFR/6g+viIUohMdWvyt8Ef735AY
         ajNVm+TcgVelBbzfhz90lbAiCcoHTqL9qkifi1VpDEqut6qtgRIc+mzkVUrWp9TiwQnw
         F6l+i7kU+9iZmMfmY+IaRgXvZEKs7aL+iqrzKQaZWMlGCJRxNOkttEqCNcPousyf0szK
         SMJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SmpX8PXu;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166461; x=1755771261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Dc1++BVJOIJjEDfSmxfPCfbfvz4+11WWHMbAMG7BUXc=;
        b=TzmMZpBF5IS37pxg8Dny6dlKq0y67KYyRt2jqkAIa2QuQA6nHNSkCoMEhFLgfyToKf
         /1YzaL5r/xig/RZ00wqB7QeKnuWJcxoMpWswpvEzdJKtPCsHqU0EnHJiA51283J5CFqt
         CgkeGvlQVLyIMiOqVMPLuEenftI+rKn3cnRtjMrlkCcZYRh8PFe3PQsRs6gFXGeFZnv7
         L03YVEb5jRDRhjRY63ntENzi9iTPxIrK005VWGmDPqI+wHKgiyxl9pYREUUc1Kqx9SRk
         rLIPtBsgJVXH1vLCk8Z/21GrQZVIfk28GKwyhZe0iuVbOdkRJvcyvRxwNP5cNiDm8BQH
         GBUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166461; x=1755771261;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Dc1++BVJOIJjEDfSmxfPCfbfvz4+11WWHMbAMG7BUXc=;
        b=kjDOQ8da5T+hsjypg1Z+2A++TMhf94kpnAjcjUcceL32gZgN/GXojVnvvyzMoWTykI
         9XVtKh/Y3zn7oZztn34SsTUiFl1gXUkbYV1rnjKn72R3PEp1wsFgmuGj5FP8eLktklIU
         PMn3VuO56+0rctYdfPY9iOG4t1GcvSEgkPeW5Z2ynhyTfe/ztPgf0afCjjCoYEHsS+9m
         Jmjvh6syI25aMHbBDsRxlZr5iupVdSwZT1KL0Jk/lGtQpK0lHqrmSaTdJIB//sNcwzT5
         rAg21JZTXx22rjmvPNpDVYgDtDUUPj9EdnZr5SwkFt6qoKOkgHOU5+135WurXUlk08yo
         +fgg==
X-Forwarded-Encrypted: i=2; AJvYcCUsTW0A+sHKh/NguqHiRmXT49Hf/7B6LujoNCLkVZQQVOi3V6Vbk2U3PnMHOGmQLaM3EUi7yA==@lfdr.de
X-Gm-Message-State: AOJu0YweZMxglOXxwgRXlvqYH6xIlOzzThYelkhEKLJjZcFcoCAKch0r
	hznT5jCwEjOp7NGEKupVG+itRmQ5BlXpmK+mA9rDr801MuDTCQoXv3ge
X-Google-Smtp-Source: AGHT+IFZM48hZ+AXonCS43GJtqQ8jNaiCtEPyFiwE3bpQHvZH0jJw9Xc+nHbX9M0nSNTqze0IdZWtQ==
X-Received: by 2002:a05:6214:5087:b0:707:b2f:5b8b with SMTP id 6a1803df08f44-70ae6f57f0bmr31810706d6.14.1755166460783;
        Thu, 14 Aug 2025 03:14:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdEPA5g1Q9pbzmyXXOMlAvdUG0O35bauQhx9eOSosHUrg==
Received: by 2002:a0c:f097:0:10b0:707:4335:5f7 with SMTP id
 6a1803df08f44-70aabf21027ls7558426d6.0.-pod-prod-09-us; Thu, 14 Aug 2025
 03:14:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRo8O5shkAAwWQGl7gRY4iZZFZ2cDgE3d/0HZDah9puAu1ypYo2p6XIFgfcraM2sPhNUi7XFzgHbc=@googlegroups.com
X-Received: by 2002:a05:6122:1685:b0:539:4097:794a with SMTP id 71dfb90a1353d-53b18bdcb6fmr771273e0c.12.1755166459866;
        Thu, 14 Aug 2025 03:14:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166459; cv=none;
        d=google.com; s=arc-20240605;
        b=JgfClKfrPTyCxnHrt1j0ze77uG6Hocruss31KfLLTP03o/R/cZi1kzKiKLT6USQ3Jf
         nUaCFA5Y8sTfT2kWEZtowtCWP+mseKwCjoMpLIhjixqV6tE139SynJpkzizXWGCzgNYS
         0TCwvBj+k6IJRaAcWczx4aUOfC6Ru4xwnPdgMlR0JRrD/wBKyJq3QdqSe9BKtfZN9EoC
         JsMfG3O89t/yvY6OZCfQdBIfgAmi1wjHUHM0addBUm5+dSSFZ2MdmmTL+lrX+kXy4S7j
         xHvE1qoalcSgTINV6KYhaCoQY8X6Yn3oza4RtVFSB+FijVhHlGP+OiJ1+xeJ8DpFvETc
         wTqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SxVJ7EcVndf9TgWXko8eFo+h8Krf23TH2nyXAvhfQkE=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=Y3aJe8FNxjmI2AT9ooJmhM9f8EqlxtgaxjgkMgumAey3QxvULPS9thc3OG2FQjd2Ba
         1/q5aoSQ7lf03+ARnZh/nH3SlT+LPAMs6BwaNHzBjTvZTSgL7EKR+hCjfv9jzcTehovD
         E4l1xRruQ8WVWZ/q/f0QKsqaXuCtB9wXgt/Ye0/YHwxfZmFeQZ9c9E7mmQ+ksOftv2XL
         la4C6wuGgUdBEI6yU6arsXjHSS8TENDhtsxWCiOB+WPjcfGL4hr1vnVANHRqBc2C54E1
         U5dMe/1f/da/wEYf6rbAVcUbJ25zt98AWID796RRwBZBS83Izk+d17ehfsz4021XnAkl
         rD4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SmpX8PXu;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539b01892eesi785904e0c.1.2025.08.14.03.14.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:14:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id B0AEE45FFC;
	Thu, 14 Aug 2025 10:14:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D5592C4CEFC;
	Thu, 14 Aug 2025 10:14:17 +0000 (UTC)
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
Subject: [PATCH v2 08/16] kmsan: convert kmsan_handle_dma to use physical addresses
Date: Thu, 14 Aug 2025 13:13:26 +0300
Message-ID: <fb43d745ff8fd822622932f6eb813621b75b2499.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SmpX8PXu;       spf=pass
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

Convert the KMSAN DMA handling function from page-based to physical
address-based interface.

The refactoring renames kmsan_handle_dma() parameters from accepting
(struct page *page, size_t offset, size_t size) to (phys_addr_t phys,
size_t size). A PFN_VALID check is added to prevent KMSAN operations
on non-page memory, preventing from non struct page backed address,

As part of this change, support for highmem addresses is implemented
using kmap_local_page() to handle both lowmem and highmem regions
properly. All callers throughout the codebase are updated to use the
new phys_addr_t based interface.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/virtio/virtio_ring.c |  4 ++--
 include/linux/kmsan.h        | 12 +++++++-----
 kernel/dma/mapping.c         |  2 +-
 mm/kmsan/hooks.c             | 36 +++++++++++++++++++++++++++++-------
 tools/virtio/linux/kmsan.h   |  2 +-
 5 files changed, 40 insertions(+), 16 deletions(-)

diff --git a/drivers/virtio/virtio_ring.c b/drivers/virtio/virtio_ring.c
index f5062061c408..c147145a6593 100644
--- a/drivers/virtio/virtio_ring.c
+++ b/drivers/virtio/virtio_ring.c
@@ -378,7 +378,7 @@ static int vring_map_one_sg(const struct vring_virtqueue *vq, struct scatterlist
 		 * is initialized by the hardware. Explicitly check/unpoison it
 		 * depending on the direction.
 		 */
-		kmsan_handle_dma(sg_page(sg), sg->offset, sg->length, direction);
+		kmsan_handle_dma(sg_phys(sg), sg->length, direction);
 		*addr = (dma_addr_t)sg_phys(sg);
 		return 0;
 	}
@@ -3157,7 +3157,7 @@ dma_addr_t virtqueue_dma_map_single_attrs(struct virtqueue *_vq, void *ptr,
 	struct vring_virtqueue *vq = to_vvq(_vq);
 
 	if (!vq->use_dma_api) {
-		kmsan_handle_dma(virt_to_page(ptr), offset_in_page(ptr), size, dir);
+		kmsan_handle_dma(virt_to_phys(ptr), size, dir);
 		return (dma_addr_t)virt_to_phys(ptr);
 	}
 
diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 2b1432cc16d5..6f27b9824ef7 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -182,8 +182,7 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
 
 /**
  * kmsan_handle_dma() - Handle a DMA data transfer.
- * @page:   first page of the buffer.
- * @offset: offset of the buffer within the first page.
+ * @phys:   physical address of the buffer.
  * @size:   buffer size.
  * @dir:    one of possible dma_data_direction values.
  *
@@ -191,8 +190,11 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
  * * checks the buffer, if it is copied to device;
  * * initializes the buffer, if it is copied from device;
  * * does both, if this is a DMA_BIDIRECTIONAL transfer.
+ *
+ * The function handles page lookup internally and supports both lowmem
+ * and highmem addresses.
  */
-void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
+void kmsan_handle_dma(phys_addr_t phys, size_t size,
 		      enum dma_data_direction dir);
 
 /**
@@ -372,8 +374,8 @@ static inline void kmsan_iounmap_page_range(unsigned long start,
 {
 }
 
-static inline void kmsan_handle_dma(struct page *page, size_t offset,
-				    size_t size, enum dma_data_direction dir)
+static inline void kmsan_handle_dma(phys_addr_t phys, size_t size,
+				    enum dma_data_direction dir)
 {
 }
 
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 80481a873340..709405d46b2b 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -172,7 +172,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
 	else
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
-	kmsan_handle_dma(page, offset, size, dir);
+	kmsan_handle_dma(phys, size, dir);
 	trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
 	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 97de3d6194f0..eab7912a3bf0 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -336,25 +336,48 @@ static void kmsan_handle_dma_page(const void *addr, size_t size,
 }
 
 /* Helper function to handle DMA data transfers. */
-void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
+void kmsan_handle_dma(phys_addr_t phys, size_t size,
 		      enum dma_data_direction dir)
 {
 	u64 page_offset, to_go, addr;
+	struct page *page;
+	void *kaddr;
 
-	if (PageHighMem(page))
+	if (!pfn_valid(PHYS_PFN(phys)))
 		return;
-	addr = (u64)page_address(page) + offset;
+
+	page = phys_to_page(phys);
+	page_offset = offset_in_page(phys);
+
 	/*
 	 * The kernel may occasionally give us adjacent DMA pages not belonging
 	 * to the same allocation. Process them separately to avoid triggering
 	 * internal KMSAN checks.
 	 */
 	while (size > 0) {
-		page_offset = offset_in_page(addr);
 		to_go = min(PAGE_SIZE - page_offset, (u64)size);
+
+		if (PageHighMem(page))
+			/* Handle highmem pages using kmap */
+			kaddr = kmap_local_page(page);
+		else
+			/* Lowmem pages can be accessed directly */
+			kaddr = page_address(page);
+
+		addr = (u64)kaddr + page_offset;
 		kmsan_handle_dma_page((void *)addr, to_go, dir);
-		addr += to_go;
+
+		if (PageHighMem(page))
+			kunmap_local(page);
+
+		phys += to_go;
 		size -= to_go;
+
+		/* Move to next page if needed */
+		if (size > 0) {
+			page = phys_to_page(phys);
+			page_offset = offset_in_page(phys);
+		}
 	}
 }
 EXPORT_SYMBOL_GPL(kmsan_handle_dma);
@@ -366,8 +389,7 @@ void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
 	int i;
 
 	for_each_sg(sg, item, nents, i)
-		kmsan_handle_dma(sg_page(item), item->offset, item->length,
-				 dir);
+		kmsan_handle_dma(sg_phys(item), item->length, dir);
 }
 
 /* Functions from kmsan-checks.h follow. */
diff --git a/tools/virtio/linux/kmsan.h b/tools/virtio/linux/kmsan.h
index 272b5aa285d5..6cd2e3efd03d 100644
--- a/tools/virtio/linux/kmsan.h
+++ b/tools/virtio/linux/kmsan.h
@@ -4,7 +4,7 @@
 
 #include <linux/gfp.h>
 
-inline void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
+inline void kmsan_handle_dma(phys_addr_t phys, size_t size,
 			     enum dma_data_direction dir)
 {
 }
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fb43d745ff8fd822622932f6eb813621b75b2499.1755153054.git.leon%40kernel.org.
