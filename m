Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBDOXQDDAMGQEI55JLII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id E4507B4FCD1
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:28:47 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-32bdfd536aesf3475026a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:28:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424526; cv=pass;
        d=google.com; s=arc-20240605;
        b=A+ozdreYpcy8hzPrH9Jde4b0NUbW1U90Ljx/Axq8zbvGjOg84Hyp4Uq/oondiLPwRP
         bd7uXAHrf2CfHHliSUmZ8FJgYJnLF0CusQyUp9MDsbTvIBHRnXPyw1nE8dYioIBJB3mx
         vpN3+FuEIP0VjRBzEpNx9Fp0WwV6g/gKZ/rvcIKV8lv1DmtAXFVk+pCL3Gbz6f7c3EcK
         LA1MoglORlBKLMF2Zy0+SDNLHhpoAC1B4hR8TQKuKi1MJbmOEYGOsiDPwCYj7+GkfUUN
         qffeSe3QdIvRU9JAAvsF1LzCb6RU2bLUldR5ZyziMh5U4jItjILve6NNqr1cbb5DiYzE
         z44A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=5W070xcbt128JSd85idqTeWOmdgRC+JmiSJbgP5dOqQ=;
        fh=DjEqL91pQJq7RAVKNipqPaOuMinC88n89r2Drnl+Q0A=;
        b=iBv7GqVo12q4XLncL1UlPuwKCY22z3aPebr6JL0cLuRgcaTVedg1NJLQ4IDeMKe94B
         hUHrJ6QtrTOcoCwcQJHG24uOvzk8/GpNqXR4CfLtrgynjBF34lAOlN3p9Kvfy6ql6WlG
         5084Eix007+4P9BiguJ083Mhc6Rjlq2VUX5ab2O5xuIR04676Amn47GInpfCzc4jSeM4
         i+k8olk4EerTLcOT4NZpzvzNKBhcQEoKhafn0qnHmERczrShhvxPiKRd+t6/xKYmmlsT
         qL8eTyr90h5ab+wVG+mes5uYhakK7Z7d/4W2DyDrOK0UI9uH/hnJuMR0OPHfNCxHkk3U
         8iow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jgpKjl3W;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424526; x=1758029326; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=5W070xcbt128JSd85idqTeWOmdgRC+JmiSJbgP5dOqQ=;
        b=ura5jPbocM1wO05aKb6zMVZ1q8TdnC9y14WT16XikhOul87i3U1CCWvpQ7YqYdbN+A
         ytk0yJjaMOM1MCTqPYaw8ZJKbo58noJT6d2r9C+VxY9VfgzkLQm7BB9djFx0fW3B7M8b
         Pmhtxb5VMJGH53slqOo4rOndAT02N0aUZN3CvxOCnS7dpQdbSOx/9gWCMNAhB77fAJmd
         ctBIwHmGgoIGwQ3lFrLDrlVUEPQLFfsE82M7EplepA0YchL2i5075McMAJNVkioaMmRr
         z8fArysY5TahYgBgwd9ygNvClW+a5M0lJenIVlGxihiTsfnM7rqpU2mPjv7knwP2btJz
         MU/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424526; x=1758029326;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5W070xcbt128JSd85idqTeWOmdgRC+JmiSJbgP5dOqQ=;
        b=TQpO7glqw8UanJjnBiy6R3kx3bhLXo3c2xdqPY/ujcaympbEFkB6SZ51J40XUZnsKw
         jaSx6Emg1HypM+xJ5W7GTvCviQGFA8m4wNIE8N70Q1rfYspN7A1HOBJ8ZnqRwUx0F1K4
         Rprsggp144WOqCmtGiW3pW0HFHAsZaHrdh1AHG10jLBH2uDfFtlxmcpmJvPkEsQpihsL
         yQ6SHKtS/Sr+oijh72zOnM87Xr6/RxHYsq0HeK6aypzyuG+/9OSSkdC1YjZ72mxR+3RP
         tqJ3BvUf7jcXzYIy0TV+1bWWq40mIx3hrv+2DY/Gcp5bTAon8gZ/4qxmwZRBfgs75BAa
         UXJg==
X-Forwarded-Encrypted: i=2; AJvYcCU2oL1ydjDvKqzPksc7Ga4Aijcb6qNHMCm2YGkCMgc6jtFzZ63NXTZjkzkXzyUYbLfPcF+12Q==@lfdr.de
X-Gm-Message-State: AOJu0YyaSmJK2d7LM+wKsAO5sLuQJV+CPbzHug8WqPTqhMXqjfwGhgoZ
	XI7FxlLqUU9pryM3lWQiOT2eaUPkAN/63i3QodfH0HZC5wh6LApAeGP+
X-Google-Smtp-Source: AGHT+IFTPlxr15XWRhU2Z14P6uaZLAFtPMkF5OOGwWbkur5tX1Vjd/TimC5LjYn0kaKIoRKf3FLcNg==
X-Received: by 2002:a17:90b:3948:b0:325:25fb:9128 with SMTP id 98e67ed59e1d1-32d4509f035mr14481058a91.9.1757424526076;
        Tue, 09 Sep 2025 06:28:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4meNR1yPYX4b1O77bKPQoerKxXm5davI5InbrRlmhvQw==
Received: by 2002:a17:90b:2f8c:b0:329:f229:7c46 with SMTP id
 98e67ed59e1d1-32bcaa02c8els2543616a91.1.-pod-prod-00-us; Tue, 09 Sep 2025
 06:28:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUozwFyjBfiiOKsnJLXoTw6JdEKjYs5syRdCnnAl5Ehm1wHgF3HS0BmndXgIQEG2KACeWIR/0JyVWU=@googlegroups.com
X-Received: by 2002:a17:90b:1b0d:b0:32b:7d35:a7e6 with SMTP id 98e67ed59e1d1-32d451bd8efmr14986643a91.18.1757424524459;
        Tue, 09 Sep 2025 06:28:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424524; cv=none;
        d=google.com; s=arc-20240605;
        b=Vm49tANoThNv64UMVsTTExmQvVSy0uj5tjGLkUEgvTtNfZd6DqeRoVFNQ7VETcnbF/
         Q+a9xjR4624B/PxYSQdftie5ZpNe4pxdXZyfsEXHqIA463vjxZZRCzoNlVqT9jDPORJN
         Ziy0s1jG3QXvSbQkbQXoVnuQsT+0Y4TAyzD/6fHQLRwZgf+Kfn9cGjsOAwGNQ6eOV/ky
         m5wtTDdW0cLw8j/d/R2jrz+J2ZHUDEtAtMKqC7ehpwq0gesydHyUhryxwRoNkymp6TSy
         bnf4189vrxkZx1uVNWRmcPeSTqH8gPoI0IsLHb+3JXRBs/7tdgjtxE0jbIn6KbmHkLL8
         CU9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xhEMQr2SWkJmlxMyFOKNbyDmG9QYmuLcjXIMFwlZ4BU=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=eu2BM0UNkvZVi7ESREp/X6gbpeYDnaqiXI8rJbnBCaA1l515CqQBMQX8149Zz1h80j
         fkzaGZ+uxoeUMx8PeBiOELhHH9y+YATWhlq+qzWX9Y9C+50PSL4YqneKA0HMDE0qSQCH
         WXb1HOgtd1rW/evMx0STtoHAr35cJHXE/hmd6klnZ/1VOgv4Z4H//RWPtLYwN1Rg1TEw
         M1Ttz9NbrkCug9M+rnnKI+StySMXtb9oUn1z+1c4XEhKMiHO66SWGURy8NqmA4aFbGqv
         b3MEJA/yrKexyXJJUOHxc8p2SpmJgMr3CU3894Z7//uPoIv8+6F6nOMc0Eh1iCRWvZ5e
         BLAw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jgpKjl3W;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-329e4591336si752047a91.3.2025.09.09.06.28.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:28:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 5024C433EF;
	Tue,  9 Sep 2025 13:28:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 66D52C4CEF4;
	Tue,  9 Sep 2025 13:28:43 +0000 (UTC)
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
Subject: [PATCH v6 08/16] kmsan: convert kmsan_handle_dma to use physical addresses
Date: Tue,  9 Sep 2025 16:27:36 +0300
Message-ID: <3557cbaf66e935bc794f37d2b891ef75cbf2c80c.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jgpKjl3W;       spf=pass
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
size_t size). The existing semantics where callers are expected to
provide only kmap memory is continued here.

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/virtio/virtio_ring.c |  4 ++--
 include/linux/kmsan.h        |  9 ++++-----
 kernel/dma/mapping.c         |  3 ++-
 mm/kmsan/hooks.c             | 10 ++++++----
 tools/virtio/linux/kmsan.h   |  2 +-
 5 files changed, 15 insertions(+), 13 deletions(-)

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
index 2b1432cc16d59..f2fd221107bba 100644
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
index 3ac7d15e095f9..e47bcf7cc43d7 100644
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
index 97de3d6194f07..fa9475e5ec4e9 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -336,14 +336,16 @@ static void kmsan_handle_dma_page(const void *addr, size_t size,
 }
 
 /* Helper function to handle DMA data transfers. */
-void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
+void kmsan_handle_dma(phys_addr_t phys, size_t size,
 		      enum dma_data_direction dir)
 {
-	u64 page_offset, to_go, addr;
+	struct page *page = phys_to_page(phys);
+	u64 page_offset, to_go;
+	void *addr;
 
-	if (PageHighMem(page))
+	if (PhysHighMem(phys))
 		return;
-	addr = (u64)page_address(page) + offset;
+	addr = page_to_virt(page);
 	/*
 	 * The kernel may occasionally give us adjacent DMA pages not belonging
 	 * to the same allocation. Process them separately to avoid triggering
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
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3557cbaf66e935bc794f37d2b891ef75cbf2c80c.1757423202.git.leonro%40nvidia.com.
