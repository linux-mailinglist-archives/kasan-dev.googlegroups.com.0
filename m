Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB2HN63CAMGQERDSJ35A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 658D8B261F4
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:14:02 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2445823e49fsf8357725ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:14:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166440; cv=pass;
        d=google.com; s=arc-20240605;
        b=HY6+cO34P2mqf+KR84ygzWgnNYHi0rpBzMnSZjrljKpdxbt3yyJzAU2FWnlq1w3RH4
         d+0tHV49cmhDft45AHGT2PDXTBs42bqsfGwYgRQceV04lyEodsZWVP5lojQb1T3uNcoc
         8kQ5Ze3FmZnfo+dGHqW4Ox9g2W5Q+9KJ9WMBceK46OhiL0VTJtmBvfPL6+fV3oh/uVdt
         R7cRe4bekUFLaDbYYQNHmXyqxRqO15J0IQwEzHXLNzG4u46QmlVWafsESv15J78b/Kii
         zTa0OjZ/II7gulsZj+dWSZF37JI9AThgJObFiC30KOtiaUr+s/1e5gDRdTndIKP8wFbC
         cU6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ScnEioJR5p7KhLUcDiJ7WQ/89NpNg54Twh9qsvPt41c=;
        fh=WXUHvOXHFWAisA+uoVLUhARcwJobOoTU5KGnQqJ5Ql4=;
        b=g6wYzDMbYfjaO8hfB9TXheF2IA7Qgil4YVrxBaPTZDtoMEOq319BlKKpWPw9Le5N7L
         TFKEKIl8cOQOa6KBnN9Kw8zHfTsRJpae+bEapOxtSrFt1jIKe+qV4qDl5+QIsg5d/dfM
         a9fvH48uDdp/7Fez9X+ZuFkleR4kt8xzNpKve7/s7nQc4D2E0mWBSkserIEtwQnWUK+/
         WPnHhzMR7f1oyQHqhiNVCGLDdH5/JMk9/QnAOYkADv8JzjsbzroK1+GwjKNU1TTL+J5n
         mzR051tTg1QEHq2b1FOniLEnGSC8ctONnMDrc6/XQpl7ivuFI5tGpgwwaLv+VvH7WMKX
         +84g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iJnTdVoA;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166440; x=1755771240; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ScnEioJR5p7KhLUcDiJ7WQ/89NpNg54Twh9qsvPt41c=;
        b=E5CICtHcf5OHio2G3JSWyjqbhIycbV+ZpE6kC/xFBck9eX6LiHgaZmdQGWQXHqr6c6
         Ij6vMcs2v2PVEbDJ+ZcAABchFb5ggfYkA+ASnktT8v+igjRY5SB5Gb1Y7vilB537Nphk
         ikqcr63k0B9MaY9jL9sKvdLENMeKhDIPAuYq26GWZqNHvnPWVSX1XdA++bOFy36HB9SN
         DSjQSiMYrLJs06mggHgQ6zxotGkwFXdfCSlap8SU1Os3Op7COat53+lr3agKXDKFJ4Hn
         SjIcJ6iVJGpBpZW7WqB6JpCg/cn+X3E36GJr3fhGEPkTNeMcu2LwOuDMprETDXsLcLT/
         LBQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166440; x=1755771240;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ScnEioJR5p7KhLUcDiJ7WQ/89NpNg54Twh9qsvPt41c=;
        b=v1n69muCEIaNwsekLaCx6V2G9tibZZMOF5UokySuzULasOnZq8qfRlk7n0a19uLq+/
         4+ZbnIeIi9XTt0BRwhUNzmvMKx7SlhbTonViLRRdeV/p0AUufPdhViL7EtNIFB7EX3Ww
         M+aQ8+oeAdaFShI3pO4ndrcCvJKptqgUD7QkxxzJGtJZMzs2Qqm2yDdlEcar8Cc6RcRy
         CKpDTdrOxG4ML6ysQJbCCKJTaq4UvqW5s2i7MFvxAufR7MII3LgYo/aa2eJJlwliMA/A
         fBWcOmEFDJ4Bapy9n4LfghybpVF3gAH97zd+USytqp4/YHa3Q+IdNfkj8EOTx2D/fIky
         DcAg==
X-Forwarded-Encrypted: i=2; AJvYcCUJXCi0q1JfThTLbBKEy1hfZrDyu1cKflXP2GOKhKxM6Rhwk4OqCyZ+mOrpVVrbsAhLmRkzgQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz+Qb4Pya1Dg53aGHGhttdNGmn6h7zF7DDcmQW0eL8LD9NAsWu7
	4T2acMaHECTMd+6iSau2KVvxPw0YLC7faT/TQwTVlNonfJhcqVwz7qxK
X-Google-Smtp-Source: AGHT+IGeeo90FQD1TDziqFvoIU7Fjxywnwr81ABjKRnKCW3jXIK1eKmfvB1Ki7QcNJsL/2ADZqj0OA==
X-Received: by 2002:a17:902:cf10:b0:240:c678:c1ee with SMTP id d9443c01a7336-244584a204fmr36349705ad.11.1755166440472;
        Thu, 14 Aug 2025 03:14:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcvIxosW9x59ihGtxT769i8yLaL6/A6n4L7p+jOxKskyw==
Received: by 2002:a17:903:1b08:b0:231:e735:850a with SMTP id
 d9443c01a7336-24457570f66ls9976825ad.1.-pod-prod-09-us; Thu, 14 Aug 2025
 03:13:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzkeKorTzb8nVdD+FSa2aqJtp0qcOdmH5MBUEG+2+/nonWOvPO9mF5HpP/i1Hj3BKMwyHZArRrifE=@googlegroups.com
X-Received: by 2002:a17:903:4b2d:b0:242:fba2:b8e4 with SMTP id d9443c01a7336-244586f2eb9mr34624665ad.56.1755166438554;
        Thu, 14 Aug 2025 03:13:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166438; cv=none;
        d=google.com; s=arc-20240605;
        b=j8z5xJRte1qnjxWxOGmqD34dpR4YiTU9b3icqkUirIlNSXiLesA2dQ1U7OAb0nMvFh
         t/ts641S/O0+c4igYYkIFofc97zr7q+aI7hP5FbvHk0+uhf0QxdMo1Mbgc29zaSRiO/S
         ciWuGoNpQnDFFJz18P3HoibEwysl1I8vRRPXdJNmruo0q6DBo4OTqo0g+CCnioWJ1xc9
         ILS/Gh8kxOyTXXHFx7faqREPbjyxs+J2YIJeF0ezLc9PR1jJlnS57vKzrrM6b4aqGOOD
         Oz04kyBZSmXXvIUJfPjI7FWggdrLeRhmVH0HoVqf3RJnoUn7uGj6nJrhI/kR7rTmp6pq
         LE9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=v3bm79vW8TmRkbMs8v1DEAwPfoV8hY4/GHRwYQJsC0o=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=IWfLnf4wARg2XByeitHzvCQs6EeN4ara1iYR8EYp2kj1V66LSApmxGv5/GcFAY14vd
         0n43nFeSZ8v2wFI/FxBO0dJa+G0fP4GXlK4xcziQB+vBk/BYFzEcn+y5wI3wya4/KP2q
         UGVE0UdMaSwQeKoJbjTnjmMQdD/IP35zVxTlPIBSmtjyFUbN6qZCUPhNTVTZZCvsYka1
         sA8+Y0y1n1h6/ES+yvuAU7dJ4blhU9W/OF2IXwTRohYJrRWp7pyg+0oJ1ilIDaoQ1ihd
         StAhfZkxqRInBRVDWt7hmARtGQONWi+DrVJDcXlq4eWz5pJYvgqgFf/cf16+x41T6NWU
         gamA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iJnTdVoA;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241d1fb2627si16034515ad.5.2025.08.14.03.13.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:13:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6725845594;
	Thu, 14 Aug 2025 10:13:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 80CB7C4CEED;
	Thu, 14 Aug 2025 10:13:57 +0000 (UTC)
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
Subject: [PATCH v2 01/16] dma-mapping: introduce new DMA attribute to indicate MMIO memory
Date: Thu, 14 Aug 2025 13:13:19 +0300
Message-ID: <f832644c76e13de504ecf03450fd5d125f72f4c6.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iJnTdVoA;       spf=pass
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

This patch introduces the DMA_ATTR_MMIO attribute to mark DMA buffers
that reside in memory-mapped I/O (MMIO) regions, such as device BARs
exposed through the host bridge, which are accessible for peer-to-peer
(P2P) DMA.

This attribute is especially useful for exporting device memory to other
devices for DMA without CPU involvement, and avoids unnecessary or
potentially detrimental CPU cache maintenance calls.

DMA_ATTR_MMIO is supposed to provide dma_map_resource() functionality
without need to call to special function and perform branching by
the callers.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 Documentation/core-api/dma-attributes.rst | 18 ++++++++++++++++++
 include/linux/dma-mapping.h               | 20 ++++++++++++++++++++
 include/trace/events/dma.h                |  3 ++-
 rust/kernel/dma.rs                        |  3 +++
 4 files changed, 43 insertions(+), 1 deletion(-)

diff --git a/Documentation/core-api/dma-attributes.rst b/Documentation/core-api/dma-attributes.rst
index 1887d92e8e92..58a1528a9bb9 100644
--- a/Documentation/core-api/dma-attributes.rst
+++ b/Documentation/core-api/dma-attributes.rst
@@ -130,3 +130,21 @@ accesses to DMA buffers in both privileged "supervisor" and unprivileged
 subsystem that the buffer is fully accessible at the elevated privilege
 level (and ideally inaccessible or at least read-only at the
 lesser-privileged levels).
+
+DMA_ATTR_MMIO
+-------------
+
+This attribute indicates the physical address is not normal system
+memory. It may not be used with kmap*()/phys_to_virt()/phys_to_page()
+functions, it may not be cachable, and access using CPU load/store
+instructions may not be allowed.
+
+Usually this will be used to describe MMIO addresses, or other non
+cachable register addresses. When DMA mapping this sort of address we
+call the operation Peer to Peer as a one device is DMA'ing to another
+device. For PCI devices the p2pdma APIs must be used to determine if
+DMA_ATTR_MMIO is appropriate.
+
+For architectures that require cache flushing for DMA coherence
+DMA_ATTR_MMIO will not perform any cache flushing. The address
+provided must never be mapped cachable into the CPU.
diff --git a/include/linux/dma-mapping.h b/include/linux/dma-mapping.h
index 55c03e5fe8cb..ead5514d389e 100644
--- a/include/linux/dma-mapping.h
+++ b/include/linux/dma-mapping.h
@@ -58,6 +58,26 @@
  */
 #define DMA_ATTR_PRIVILEGED		(1UL << 9)
 
+/*
+ * DMA_ATTR_MMIO - Indicates memory-mapped I/O (MMIO) region for DMA mapping
+ *
+ * This attribute indicates the physical address is not normal system
+ * memory. It may not be used with kmap*()/phys_to_virt()/phys_to_page()
+ * functions, it may not be cachable, and access using CPU load/store
+ * instructions may not be allowed.
+ *
+ * Usually this will be used to describe MMIO addresses, or other non
+ * cachable register addresses. When DMA mapping this sort of address we
+ * call the operation Peer to Peer as a one device is DMA'ing to another
+ * device. For PCI devices the p2pdma APIs must be used to determine if
+ * DMA_ATTR_MMIO is appropriate.
+ *
+ * For architectures that require cache flushing for DMA coherence
+ * DMA_ATTR_MMIO will not perform any cache flushing. The address
+ * provided must never be mapped cachable into the CPU.
+ */
+#define DMA_ATTR_MMIO		(1UL << 10)
+
 /*
  * A dma_addr_t can hold any valid DMA or bus address for the platform.  It can
  * be given to a device to use as a DMA source or target.  It is specific to a
diff --git a/include/trace/events/dma.h b/include/trace/events/dma.h
index d8ddc27b6a7c..ee90d6f1dcf3 100644
--- a/include/trace/events/dma.h
+++ b/include/trace/events/dma.h
@@ -31,7 +31,8 @@ TRACE_DEFINE_ENUM(DMA_NONE);
 		{ DMA_ATTR_FORCE_CONTIGUOUS, "FORCE_CONTIGUOUS" }, \
 		{ DMA_ATTR_ALLOC_SINGLE_PAGES, "ALLOC_SINGLE_PAGES" }, \
 		{ DMA_ATTR_NO_WARN, "NO_WARN" }, \
-		{ DMA_ATTR_PRIVILEGED, "PRIVILEGED" })
+		{ DMA_ATTR_PRIVILEGED, "PRIVILEGED" }, \
+		{ DMA_ATTR_MMIO, "MMIO" })
 
 DECLARE_EVENT_CLASS(dma_map,
 	TP_PROTO(struct device *dev, phys_addr_t phys_addr, dma_addr_t dma_addr,
diff --git a/rust/kernel/dma.rs b/rust/kernel/dma.rs
index 2bc8ab51ec28..61d9eed7a786 100644
--- a/rust/kernel/dma.rs
+++ b/rust/kernel/dma.rs
@@ -242,6 +242,9 @@ pub mod attrs {
     /// Indicates that the buffer is fully accessible at an elevated privilege level (and
     /// ideally inaccessible or at least read-only at lesser-privileged levels).
     pub const DMA_ATTR_PRIVILEGED: Attrs = Attrs(bindings::DMA_ATTR_PRIVILEGED);
+
+    /// Indicates that the buffer is MMIO memory.
+    pub const DMA_ATTR_MMIO: Attrs = Attrs(bindings::DMA_ATTR_MMIO);
 }
 
 /// An abstraction of the `dma_alloc_coherent` API.
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f832644c76e13de504ecf03450fd5d125f72f4c6.1755153054.git.leon%40kernel.org.
