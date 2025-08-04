Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBEOWYLCAMGQEUYPJ6DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B5CAB1A1BB
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:44:03 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-2400499ab2fsf37332585ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:44:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311441; cv=pass;
        d=google.com; s=arc-20240605;
        b=TakL4UdhrJ6Z2oj4UsSSwamT3uDvvcyx4WbYCTmA8QCHLR+TrEaV0i3md0THytVwJ8
         Ee5tRoF3oQXeaUxHISmL97U3j4s0afteIGBoh4f5iclsO1u6lHXj04oejW24KUE1vClH
         Wlguck0TKtchAY8zTU97XSOlfn4sB8e6gSD1cXrx3jNRDrBP1Du8XnFkeUpMcFN1dWSY
         NdJ+drQodyCR0os0psEXRSzR0gWcvs+jh6gDllmyQbX2Ga4kF/JLZSBe0sHjUS0TKLAT
         aBs9g8rOSwB19MFXPCh/alSF5UbSaIJR672BeG6hom4A6ksHXWs6NFLEgpVXmjoOHg5s
         LADQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Rorb+x6k5OSyB8Kh78zARsryWqjBvXllgu4PatZqnqI=;
        fh=jEm+DtSgCqc4t6OnYti3QJYoxoE3Q/9rSGqgktidNsM=;
        b=Cr/ItRkTAnaTUcLmlhOD8n7BH0EBdRY01weWMBdPo+tNH0dt2vbX6ahO4hnTvSw19O
         E+4C3pLWiRpwQ+UFcABvP7KMyoKRsiTNjlzU9tViunGgsfpLJrnuTGLnln7EeGWQjSIy
         txmDa4uKWHxJJFxH93qH02aoAcLDzdiRipJ7d4N/8xACBsOCpB7/RKqUQq3HPB9ZbtR3
         UTBoN0dZNMDiFUGMavFrNpIM++/LBU40gHY+EmUle74UV2QcEQZvxe7XV7Yb5DuiTziu
         4EN2LU3kxl0qUHLxNO8VY38ZxbX+dl9vHvtW7owGUGD6oZSnjN3I4o0A3xg8j1FPc1hm
         Duew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=REzkJIVP;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311441; x=1754916241; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Rorb+x6k5OSyB8Kh78zARsryWqjBvXllgu4PatZqnqI=;
        b=vH9ALbcrfPdwJNTEtGHmNScAJurU7zddwDw3tcEsGAwDMzV+wJ/4Y+ItGLhOsoB3+n
         4xdHCFak54W1o+/diq8ngjmc/2vBzTA4WAbpuAIdp4R8ma/lJ0cu7V8rlnHoFNVeTXNr
         i61SOxJoWsklGt0HmtbN24imG+t2XVUmQm4FG41XGh0RYrGoNxID4mdB7hISHhv1gWyS
         z1Bo5JXWU0BQoUCcDgor98qglSmBKjohDVSNLHFe6zcXNaDzXnFa0i5OHbVYJzH/dcAZ
         sxBK7AeGXnaz0cFblc2J+pqb2L7CF2xMrkxqn3fOGaOMNxwOVyN9lFzG+atCzqqxnR+s
         CNKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311441; x=1754916241;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Rorb+x6k5OSyB8Kh78zARsryWqjBvXllgu4PatZqnqI=;
        b=sevm6X5Q3pfiXS39mrI/3d1JhsnlABBjzPlzbwRNgnvIamlovE/9h8BGKPklgJpele
         kLe3u11Mr3+gvYpRUYI4H9ycRV3P/I6Ns2Ntc1MGXJjWztsifIvV1dm0DwpqPEmDpcSs
         KkfgSFoCBZAn+tXRzDdARw4vAg2DsRy+Wn8uoNIIkZ8ZahOQ5+i8IUl/UsKXxC7Nhdpu
         BGG+DMlNOplx35eOLSgmEOvtGm+TMGZ/zlawr7eKqNx3Dq66dpGUY4awUs4DkiMRCbQ0
         ec2nuNZKBz5ftipZkCOR7z3um8AGKjXDjg+0qBHOQmjjz6hnPXv9uO35ZiUvpQeNlnOL
         hYMA==
X-Forwarded-Encrypted: i=2; AJvYcCUSHFM1pOtWVq7F7VUklwC8PGw5TlbAaUnJ/T4/FurrvIn4wBVKPhCPauLkiFts9PHGzXbF5A==@lfdr.de
X-Gm-Message-State: AOJu0YyrVwNzIndUw3icl5u06j9435GylVJPtUZFDx89DQaxuxpqhX2C
	GgRHCDsU/vZNUL37aJZeIFRJvUNCQSf/47gozsGPO30epm8sv3drQEEi
X-Google-Smtp-Source: AGHT+IF4Bnkdw8x/BktjVR05mA/1YB/1n87gDNeZunK1i3kU8bA98yxLFdUpgYx/GI/ekxyVr3szqQ==
X-Received: by 2002:a17:902:e751:b0:240:6fd0:25b7 with SMTP id d9443c01a7336-24246ff846amr143447045ad.38.1754311441403;
        Mon, 04 Aug 2025 05:44:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfG5PIOYhSAA3+XK2qGEojGiEqFiR1K/DrmS/GL0nkUMw==
Received: by 2002:a17:903:d1:b0:23f:ed14:432b with SMTP id d9443c01a7336-241d1ebb53dls27675155ad.0.-pod-prod-02-us;
 Mon, 04 Aug 2025 05:44:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbzpwZr51n1/9uGGrRLUh8/tG8jfDnIS5y6tQ/gI3TNjv6lwSjBjryTzZqyfe3kOQLruU/bkhqwyk=@googlegroups.com
X-Received: by 2002:a17:903:124b:b0:240:8717:e3b7 with SMTP id d9443c01a7336-2424703f3a7mr110071905ad.51.1754311439941;
        Mon, 04 Aug 2025 05:43:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311439; cv=none;
        d=google.com; s=arc-20240605;
        b=BOAQvWLhz/L1wY4np4B1yCS70bNSNUYX2waZgD5LhZg9HXQPuTxzdDCbqK+YMdFXmA
         kn3p1FvHBk6VAB/qrDB+qYM8yBqMdsaVtPuZhtpUrQ9FUyhtHgQbmtJOekJPUODa9lLt
         N3wkGlxTnuw9WmrtLVnRRxxC6LJJBkvqeaH3pGwM1o49rQeYdTT64gvRJ9TT2eY1lFcs
         RwxlI86QlFY2MgbiVomye5t9Zw0r28V5fsYEW7LM1zjxtSlnWOdoibR44nCFVPg23/Cj
         5uyASM4rjgnp72Rv2/5rjUw5wRN4NPolVOJigiZqozYVHJGxxMeNoJBfmxHjBsga2MKm
         IGUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rGuRtbHmiVjjoyecHucW808Sk+vwQ2t58s6Fmx6aNN0=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=bNAW/I1xm/VRFn7De2/vs89Ts519v8j2lvUjfCDSmvVqBrTOt7Uh2iKWIU6XUruvqz
         mBKUxILmJXleYonpyAy1E18Gsb7CMO6Ddp11zJlK82flXFQlWbTuhgVEUwhWdLtVv23l
         f7cHko8OTi9+AA/2bSsfAFsh6L9BCCPDeiDUjiZfgEBxGoTwRMBb04KDhQqNiqGyXr/2
         ScGyZRIvo5DckX0lnuy+FajR8+UpDlCbXT78spUjaQeJgrNAzCkeSapmVCv7kb7p8OII
         5pG9A19zEM3GgdJq5tPYQsYMgB43t2cBtwcYFo+NZ1qjTm5dxfnXRMoFdlnUmTKnTIbW
         MwHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=REzkJIVP;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241cec02f6bsi5173035ad.2.2025.08.04.05.43.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:43:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id BB55A43C23;
	Mon,  4 Aug 2025 12:43:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 82117C4CEF8;
	Mon,  4 Aug 2025 12:43:58 +0000 (UTC)
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
Subject: [PATCH v1 08/16] kmsan: convert kmsan_handle_dma to use physical addresses
Date: Mon,  4 Aug 2025 15:42:42 +0300
Message-ID: <5b40377b621e49ff4107fa10646c828ccc94e53e.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=REzkJIVP;       spf=pass
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
index f5062061c4084..c147145a65930 100644
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
index 2b1432cc16d59..6f27b9824ef77 100644
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
index 80481a873340a..709405d46b2b4 100644
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
index 97de3d6194f07..eab7912a3bf05 100644
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
index 272b5aa285d5a..6cd2e3efd03dc 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5b40377b621e49ff4107fa10646c828ccc94e53e.1754292567.git.leon%40kernel.org.
