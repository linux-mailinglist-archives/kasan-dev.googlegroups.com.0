Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB3MH3TCQMGQEDVFX5JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C37FB4078E
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:49:19 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-244581953b8sf60003305ad.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:49:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824558; cv=pass;
        d=google.com; s=arc-20240605;
        b=cwMyqlxjPniUuzG+6LG3fQQs8ZSJf6eIsn46jUXQ1+Wy6DnWI50LMtvu6gQsW1JlzV
         O0Q29DdIQ/PVL41G8FA9Sll4KB5019x7/uOjTB2pJR6XRn6boW6+No+NQZJmwF8a7Vyn
         uCBBNSw3bGly78YqCqM2QgX/F3YrUZRdjbjfdXIZ7T8Rowi2rCzVFBaqEGa0dAQ+nvqd
         r03dc0ZjJsPD9tVke/f3mJhL8uppAYUjToGIKRnE2pX6JnoD2wOFQLsfORcHc2OBl7IT
         2yvm/Jad6w1/gaHvbHxXYIAu/NaxgINUWAGTlW8WEUAsoF+eSeNQCEfCjP5fywshr7ab
         0IiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=DY+CDY41hOBXZP6X3Yw5JS1Dgs3sQaMeA5uE6NDxfr0=;
        fh=V51TuC5wOMLgv5SfosUp8XvqXx3nStyDsUtrhPunxzo=;
        b=RT/mnfunJVfs/vsADNAMTkujqPwLTwmNgC09Nyqks4a/K86IKXSbCnkDg1X+eIXn7s
         l641IUL4E+PiR304JlkgkDjxtEg0N1J7C+8qwFWDMqNgAwIqD8jxt2fFMFvAm7zjmoaU
         kan+suV8O4fIqk+TJhoZasqdGTcMCDL9ysUwlAgnPbFtG5k1V0JGpWPVMIxiQi/xzd3h
         RatMYeQc712fwu80e3mzCELQr1i9OyBvMgRHRdzAlNBccWFZ42FsC6Re6tvRAYLCncq2
         j8D12IS3oK3f0PSGXwH0xbn72PVBBmfQWsbPKnJDC1Wq4pudVehrCwj6KARwnXacO7zY
         OVgA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qNA0rpdI;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824558; x=1757429358; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DY+CDY41hOBXZP6X3Yw5JS1Dgs3sQaMeA5uE6NDxfr0=;
        b=A5ItSLnnH/rkfRgOPt3EsBWDnXtUZvXXz3rBvO/H7W62QS7lzb9dFoyaBP1m8bdFB3
         VM8hUdFei0UvxVhJyerM6iCbJZL8ACflBtKHCkKzccwzMGdrPyuA/x0IPNBQY3hOOOC0
         6qKyx4x6/fTC7T5peJL3uNjnpbgMNAli7kx5A4UpCJveMqbv6wYXTX32P7B0/eMCtZOG
         9xPBUNm2v7mKvtmIqYa/1OXdGjYebZsec3ntqhZba7BGqcrG5wUGARyOid1fKT/LfvwC
         mvQSPyyuKfxIcL8V3evUq/bFZcIntA6lA/WWIe2cQp1ElXgxbo/56xt5GaOVj3qt+v9P
         Jb/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824558; x=1757429358;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DY+CDY41hOBXZP6X3Yw5JS1Dgs3sQaMeA5uE6NDxfr0=;
        b=GyV5XDva3p+RXMJfWDJ61DM4btF1Jue3vLCWu7GuCnWx2dcLxQ4lgH7V68O3cgp17q
         zRdKIChx3EHcXw/Ho15gjqSkLxWE9Ucpo2y+LUyYxXQ/GWfVWmY+h8xhfMs0qXfrWwrZ
         r6Mc5hh4015B5yo5plEs+03yeSlFZ7axKUJ7JS843RrTUmY2bIjdminw4Pk2V1R739R4
         +SsGNAOEPs3YyfiWVEG19jnzpt4zgL50ciYzNmlXCW8gONHL9SnCv1m5tL/cCyKf84su
         l0RXl1o47SKLmEcrcrp3rsMnPwMRH0WwsRdABt8rzQzTF/SrSjpVWJzaLHdsBl/JExI3
         H/lA==
X-Forwarded-Encrypted: i=2; AJvYcCWG9BaMVO1CaWVi/l8thEV8/zVRRAMsJ580SJpLguO6fS5mMVzWwU1suL+iNLJ+bOaYMtJIpQ==@lfdr.de
X-Gm-Message-State: AOJu0YwATVm7nxOLTknro1WaAXKeweNZqdrUJkahlSabFdoJXKoT/2JS
	uwGNoulmzPtc7jylRDVfKcVYXaAqBykLdo8e4B7eZb5QEBd2u61zsrnC
X-Google-Smtp-Source: AGHT+IHIrY6GLX31ogSFmDQ/IuIhnYzKAeE3/x/RotwH6afKimkOgMSaaO/Zh7CB1PZttrah1jEjag==
X-Received: by 2002:a17:902:f644:b0:249:3eec:15c5 with SMTP id d9443c01a7336-24944b76996mr146988285ad.59.1756824557973;
        Tue, 02 Sep 2025 07:49:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfWmZtNUFGrSJog1RW8D44lpiyX5BSZpRjuDNmA2qlJAw==
Received: by 2002:a17:903:3111:b0:24b:1ac1:a034 with SMTP id
 d9443c01a7336-24b1ac1a366ls5208685ad.1.-pod-prod-05-us; Tue, 02 Sep 2025
 07:49:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXB+y0OctNzdDte9MjpeHlv6M+honqvGKJpYYInJ/kLOwbzdXphgplMlhv7WSq3Miwx/+HSuxPsqgg=@googlegroups.com
X-Received: by 2002:a17:903:ac8:b0:249:1440:59ad with SMTP id d9443c01a7336-24944b1c41amr163242155ad.35.1756824554352;
        Tue, 02 Sep 2025 07:49:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824554; cv=none;
        d=google.com; s=arc-20240605;
        b=P35GKxg9zRSg6BEyAZrwnjNBlkNgtK66kGZI+RG7X3HGvy6DnUvkduSWJ4H0z1vN2E
         R1UrlS79TLECcFY/XVD8ykba2Mrcrs6Z7otG7BOYs+KiL9iOgyo9sUOkaooKOQN1mr0U
         tYsanRRbM6zWq5nyhD6HZqO/KYj14GRjRKDwy+NfTi41ntd35aLSUJ8gvj4xmp8j2+v7
         uC7g8JmQhOpHKuvNNX890ApT7o7gFmi+9uPEQJD7sM9Bm13rEInzuV6Y760a6g2FTXdd
         dsqdS/8F/t1uzCc3u2mqohbwBDFxZj586PqxEF3e+EyIinXlTHcHrpX6qFSCX94GqOr3
         9OYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ywULpGaIgw2EWnFsajimLiQWkrdwpqvM3asq0pAoqyU=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=b0x+LIEUr2JH9EfXcuy7HYKOAPbA0/Gu5Q9LGA8U0Mjaq3LjVYWsBHMkuhhqZhSebV
         KgWUt7WrS52uuvcFrAKGs7cX2yO5Qe5xKuvA7IwnHM7s+IjbgPdDW+WYn7hhQKlc0w1l
         jyLWVIb9Ab9T3eh2n4hIF+WeqfX476Bic33/KJaOB2s2x6JwGqiK1erzqsC18YEqtnHU
         zo880dugB0CP3sJefjgTX/V7aWYTznX0s7VmQDOFSASJ9G2yjjfKEmnLBWz7vRpRqfrN
         Myv7EwUjufWKrNaZUwLIqSIbKU/apdei/1TnJF+B/M23Z0YUb9Npf5DuHNmYWTlZH8YB
         y8Pw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qNA0rpdI;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-328027692f6si353029a91.1.2025.09.02.07.49.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:49:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id F0AD744942;
	Tue,  2 Sep 2025 14:49:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2D3AAC4CEED;
	Tue,  2 Sep 2025 14:49:13 +0000 (UTC)
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
Subject: [PATCH v5 01/16] dma-mapping: introduce new DMA attribute to indicate MMIO memory
Date: Tue,  2 Sep 2025 17:48:38 +0300
Message-ID: <9cce2a2bf181edacb33151388caa47725f780907.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qNA0rpdI;       spf=pass
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

This patch introduces the DMA_ATTR_MMIO attribute to mark DMA buffers
that reside in memory-mapped I/O (MMIO) regions, such as device BARs
exposed through the host bridge, which are accessible for peer-to-peer
(P2P) DMA.

This attribute is especially useful for exporting device memory to other
devices for DMA without CPU involvement, and avoids unnecessary or
potentially detrimental CPU cache maintenance calls.

DMA_ATTR_MMIO is supposed to provide dma_map_resource() functionality
without need to call to special function and perform branching when
processing generic containers like bio_vec by the callers.

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 Documentation/core-api/dma-attributes.rst | 18 ++++++++++++++++++
 include/linux/dma-mapping.h               | 20 ++++++++++++++++++++
 include/trace/events/dma.h                |  3 ++-
 rust/kernel/dma.rs                        |  3 +++
 4 files changed, 43 insertions(+), 1 deletion(-)

diff --git a/Documentation/core-api/dma-attributes.rst b/Documentation/core-api/dma-attributes.rst
index 1887d92e8e92..0bdc2be65e57 100644
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
+functions, it may not be cacheable, and access using CPU load/store
+instructions may not be allowed.
+
+Usually this will be used to describe MMIO addresses, or other non-cacheable
+register addresses. When DMA mapping this sort of address we call
+the operation Peer to Peer as a one device is DMA'ing to another device.
+For PCI devices the p2pdma APIs must be used to determine if
+DMA_ATTR_MMIO is appropriate.
+
+For architectures that require cache flushing for DMA coherence
+DMA_ATTR_MMIO will not perform any cache flushing. The address
+provided must never be mapped cacheable into the CPU.
diff --git a/include/linux/dma-mapping.h b/include/linux/dma-mapping.h
index 55c03e5fe8cb..4254fd9bdf5d 100644
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
+ * functions, it may not be cacheable, and access using CPU load/store
+ * instructions may not be allowed.
+ *
+ * Usually this will be used to describe MMIO addresses, or other non-cacheable
+ * register addresses. When DMA mapping this sort of address we call
+ * the operation Peer to Peer as a one device is DMA'ing to another device.
+ * For PCI devices the p2pdma APIs must be used to determine if DMA_ATTR_MMIO
+ * is appropriate.
+ *
+ * For architectures that require cache flushing for DMA coherence
+ * DMA_ATTR_MMIO will not perform any cache flushing. The address
+ * provided must never be mapped cacheable into the CPU.
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9cce2a2bf181edacb33151388caa47725f780907.1756822782.git.leon%40kernel.org.
