Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBF7NSLCQMGQEFXLUSWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B851B2CAE4
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:38:33 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-32326bd712csf5169088a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:38:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625112; cv=pass;
        d=google.com; s=arc-20240605;
        b=MKYn7+7NkZhIuX/bi7hJAGwh8ORzwLGKd3jG2uifkrpHRiDlBD7VdjYGEzrrGjXkdL
         uphHJwPKOi6uHpzAim0aXI+4R9dTp5v3m6/VD7IoyLt1oWd5EKiDRw/+A22clUeLyXyQ
         cJiay7xiGgiYgHqpXujIGSFqLuxSIojgLnX3rr/w4ybGy2BV1cza5tOKO14u0RwRvtHS
         ZJOGnWm02eeacyY74E0XMvroIuGkadOm8Wd7mnczSrpGRKTQ+oj7Y+eIBe69a+cxnWbI
         K1nHQ0RNBECbROtNKuHcxX8Lr8DI9jSWDVb5vPNmFZl1vlxunALgrpxB8oLipdfYWDJn
         xuFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ihmpX37ft0+NQ00TOBMK0+9KdIxmFXOnPAU/KOhnat4=;
        fh=jj+83EkSkxjy3gsVbfIBJLdxPkswm+O5j5sjQuyh2k4=;
        b=bIBj9J3stGxx8Kjt00CR+DwjfSH1NgX0VzAOyJAWQBueUrEHJf1PSLYzMbz5vgyvVE
         7HsExOHKLlo0VXrZ01EsH5trftscd7udqTYUfPPLKvZLELVnYyZZNjC+B6AsNHs+t+cQ
         c1uvhfw3RSmXiSZG7Medwuqzz40y/jKWBwzadJbdSYDAOFr8zSxiOLoLgBsrEE5Edr9T
         9DSkn8HoI6PNsMQPLgvTUDvCKJw3WqMVKwc3celv/kmo04H7E4SmwulCx1u20nQc9M9d
         UVdPQvnopnX8papS3fFOXiUDfAmVO/AFJmNszTixKWT1t4dgRcCb9w4NiUQF/BiAge5v
         sSJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oNMOGF7B;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625112; x=1756229912; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ihmpX37ft0+NQ00TOBMK0+9KdIxmFXOnPAU/KOhnat4=;
        b=TUy4I5N/VzQ/fnAwWamq+VgwzMCwiSRNTZyONa9gcMCDkvkJCeIFRJ5sM+1yRPBUlT
         bpk2N3JXCYQ8XJubjaHrlabM550N/jnO8nG/EdOJn7k0vopLXwWDe9v/RBYTxVg1qUQd
         fCEJj+hXrYKZWW8xmlUIWR2m/jIU64J3mc2b3DpyjuP3MqB1pweHNEnCHR32ZQs93Fs4
         6+7YDHhFmgZMHB99iEKQSnLlncpR1rJbIK7I13K+4g69IvMk7vc6EB7/D5ssDqaoXgOO
         mKbcI0VncPXdsiTyEcp2IG/y28kdcp5zJS1Gx960hrzxO6ikBLsb4wT3s/02UO4dsXs7
         dlYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625112; x=1756229912;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ihmpX37ft0+NQ00TOBMK0+9KdIxmFXOnPAU/KOhnat4=;
        b=ZuCiUrj0xj24l5F50vT7xKaC1hnv8nyLFN+A4Cnw76+Mdr4HSO+mMMEd/GR76PL98N
         XvcjGZeLFd3n5D3uWb7WemDAcxzp7c581Jg3ljfyEk6JNWqxeTdBjd9/jqPSVStdEw9D
         N2OMh0vbw9lZks88BZJErWv4/v7Vm7RNFcNox7sMZa8aMcaJykxnX0ZXFqCzbpb9WyWP
         Wp41DHrklnJyBoPQZ5ObqCBa4DAwfcXL5GxwCNCebr5z/7pU8Ga/i57iHB79lz2yUJHo
         h7wvmwoUmlqB1JJaPe19IOeVVzlWeyjieW4t1+SRREDoNsiOSExw0Nm8w4su7m+p+TPU
         KyGw==
X-Forwarded-Encrypted: i=2; AJvYcCVsgB00uw3AjfB2MFU46oItyjVTe90mu/y0pOz1w3AXv/OsLsmHz16BXOzZzVVsVWzy3vl/2w==@lfdr.de
X-Gm-Message-State: AOJu0YwbQz9QjivEmzJ/38Bf787KrEx4BrqIxt1p9lVOBt5TOglT9hU9
	mHYOS8U/4ZXBHMb75qYRYaHtgobfTdxu+0w4hpRRwgoydhsEFD93eqnL
X-Google-Smtp-Source: AGHT+IGHjgv7QDHVmK0sjGgGv/fe4YuDQw4D5WcfkhVCTM+J4+643UyMgv1EN6WKH5AWwEl/kqKqIg==
X-Received: by 2002:a17:90b:4986:b0:323:265e:d9d6 with SMTP id 98e67ed59e1d1-324e12e76acmr111935a91.6.1755625111691;
        Tue, 19 Aug 2025 10:38:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcPJNibZvnZcIuFgl3tyq/xFKpCJvkCAv4xO51tqaO9Ww==
Received: by 2002:a17:90b:344d:b0:31e:e459:4d57 with SMTP id
 98e67ed59e1d1-32326e1f42bls4858870a91.1.-pod-prod-01-us; Tue, 19 Aug 2025
 10:38:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzQbCM/xNRqLOjk7dp6g3bKTJFXTEo3ncoLpH9xjZFuaLlkGBqJQDp0fCLjDKHPtPkDAQPwhzzWxM=@googlegroups.com
X-Received: by 2002:a05:6a20:2447:b0:243:78a:82a4 with SMTP id adf61e73a8af0-2431ba74495mr256292637.58.1755625110213;
        Tue, 19 Aug 2025 10:38:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625110; cv=none;
        d=google.com; s=arc-20240605;
        b=BVX72larkJFBK6JPnGGZavTjV3/I7VvC2nwBDSMFF26lE4PuWG+EZB+Ht8z8yTkPO9
         N5CYiatezB5yZtsZA5XSMwKS4C96+AVNx8n4Yv4mpFarmF1mrp/F2mhGoy1RAGjTCzCa
         LXLLpFv9/sZDCtHbPj0ATyUzQJDK+sYda4HcRLkZvCY2t+9m6lOu0DDQswZHLsAhNrIR
         PpWwnGwG0MCm21+6ApBU3SQRMgApAui9VS1bcfKnh4tV8fGPSOu92ieuJTQd/6NoD8vJ
         bhqCCj4M9lnclCfjfu8lYBPjY5LVy4PGMhcoavi4Mt5QRA+078OXJ2Ovgh7Y+EDXqStK
         1ZFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ka+259+K8Z6BWOMZtwtkOGNuLpWgpr7XEnb69sIe1wA=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=E4q+cCCAmBfXHDKg/fvBra9XvdUxgbm/BF1ZO2D7Vr+eB68vLkFH1kCrQob/EFLAA+
         Geu8sRk7e0oImZB5w8o/+0kPT+sT7LO3mhvsKoP0bBgScSQTB1yOtN668WCkZkxuouOw
         Wcuyq/IHdOM3nn8VcNsCNrq+RDhxi3WiiSyhos4mWk72kdgujI48Rjk87chO7631ZDP5
         a0G1OIp6wKftqvu19zW4roz98Gao5cb1QB+ovmD0oJ9JwddMoJoeVvFqMI9kGrHYrTIG
         8jFnq7lhTY4yMYxWdaiRA/56hxV0EQTfaOhdyIIpva61Ef9K3plLDm1I8GmaN29XCj7c
         FqDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oNMOGF7B;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76e7d0c9020si13201b3a.1.2025.08.19.10.38.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:38:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 9FCDF5C6338;
	Tue, 19 Aug 2025 17:38:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E9ED1C4CEF1;
	Tue, 19 Aug 2025 17:38:15 +0000 (UTC)
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
Subject: [PATCH v4 08/16] kmsan: convert kmsan_handle_dma to use physical addresses
Date: Tue, 19 Aug 2025 20:36:52 +0300
Message-ID: <f52ab055c9ffa4da854afe47232c7d06d109d8ce.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=oNMOGF7B;       spf=pass
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

Convert the KMSAN DMA handling function from page-based to physical
address-based interface.

The refactoring renames kmsan_handle_dma() parameters from accepting
(struct page *page, size_t offset, size_t size) to (phys_addr_t phys,
size_t size). The existing semantics where callers are expected to
provide only kmap memory is continued here.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/virtio/virtio_ring.c | 4 ++--
 include/linux/kmsan.h        | 9 ++++-----
 kernel/dma/mapping.c         | 3 ++-
 mm/kmsan/hooks.c             | 5 +++--
 tools/virtio/linux/kmsan.h   | 2 +-
 5 files changed, 12 insertions(+), 11 deletions(-)

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
index 2b1432cc16d5..f2fd221107bb 100644
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
@@ -192,7 +191,7 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
  * * initializes the buffer, if it is copied from device;
  * * does both, if this is a DMA_BIDIRECTIONAL transfer.
  */
-void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
+void kmsan_handle_dma(phys_addr_t phys, size_t size,
 		      enum dma_data_direction dir);
 
 /**
@@ -372,8 +371,8 @@ static inline void kmsan_iounmap_page_range(unsigned long start,
 {
 }
 
-static inline void kmsan_handle_dma(struct page *page, size_t offset,
-				    size_t size, enum dma_data_direction dir)
+static inline void kmsan_handle_dma(phys_addr_t phys, size_t size,
+				    enum dma_data_direction dir)
 {
 }
 
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 80481a873340..891e1fc3e582 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -172,7 +172,8 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
 	else
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
-	kmsan_handle_dma(page, offset, size, dir);
+
+	kmsan_handle_dma(phys, size, dir);
 	trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
 	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 97de3d6194f0..6de5c4820330 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -336,14 +336,15 @@ static void kmsan_handle_dma_page(const void *addr, size_t size,
 }
 
 /* Helper function to handle DMA data transfers. */
-void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
+void kmsan_handle_dma(phys_addr_t phys, size_t size,
 		      enum dma_data_direction dir)
 {
+	struct page *page = phys_to_page(phys);
 	u64 page_offset, to_go, addr;
 
 	if (PageHighMem(page))
 		return;
-	addr = (u64)page_address(page) + offset;
+	addr = (u64)page_address(page) + offset_in_page(phys);
 	/*
 	 * The kernel may occasionally give us adjacent DMA pages not belonging
 	 * to the same allocation. Process them separately to avoid triggering
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f52ab055c9ffa4da854afe47232c7d06d109d8ce.1755624249.git.leon%40kernel.org.
