Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBTWF7DCAMGQEXFKTW4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 80203B26E00
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:54:24 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-244581ce13asf21072305ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:54:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194063; cv=pass;
        d=google.com; s=arc-20240605;
        b=WVBGK9wErASGTOqxbt14toDey1kgrQ/Q1KsSTarqaJu9hjPW/dJE/zihEDpdyaMnkP
         voDySpuQzpOf83h3KP1jYuFJp3vvIlfEtPqjyXNusBtSgUoKL5e8nosAJCOR008LKr2D
         sKrzlT1odrkqPqp4QQYh/MwBMrUNALgGHQw5VfomIJEdGD4EACVVLSwZoNFBuqFwLI4y
         EuvSZKIB4wYsm1LQVHwmZpRIUXA+83ah/99OyTHgquq5TrpzaDH0ttcAmL7IWCb22FGm
         4AYSkLWR5WFnfPeYarZ14HFCIamasJbmp9BqH82SOg/WuIYyMs1be9ojFF1Zvq8h8JIT
         xSFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=k6CAcuKvUP6OiRZwfaNhYtqjYVrmxAOs847eh1pJWwM=;
        fh=K+7oj/yjZ51VkM590Fkfc2OCQsnP/tbeG2RBMQzvf1U=;
        b=kOzpxGlhp3f68xpoKF2bV0lhZLCQVvT7lPFB34k75gdfSoTjvI1dhrYwqJpV+KUhQ4
         q6DnJKRR3p5qqN33z5U+NpiZBMnyHmFDlUgZG2yuz+tDvyu8rS5sUT+bAF7tor7qZWH6
         qbM8jRc/6LDICiX0oEPioZApQb0W+2BfCFmcIglQdVYh/NPKhfiQBc7QZGcUm4o914ED
         MI49gehDHWK4+CBlfhAcGc/OeZVUHj9Ccpjjrku8L6lpFhE+lvMav9xsH6zaAj3Vda1K
         jaUvNdiwsWX/dSr+0G6mUStu6gY3DA+dPizFGD0R1s8MoeXXIN9UhHg5YYWHgOtvK/Hp
         3Y8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=S9amqurf;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194063; x=1755798863; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=k6CAcuKvUP6OiRZwfaNhYtqjYVrmxAOs847eh1pJWwM=;
        b=uYCqpeg+jEhB9hmnAiiC4wy4qJk/yKVLTAswuLcTg4sjWtL08Ls5TpO02o6389AjvU
         z5o9apx/WZZRB6HkENWWxLN7ET8hZlSjkpSKjuQCT0cuu+hs70HNZscfiji+T8UNprm0
         yBGx+EWLaVo2x/GzjlMTzg+0inFN3+oXzOSH7O/5OsmI9NUQBmYUHOrp4eJeA60aD+eI
         hKN/ZHxNltqijxGHU82Vw2y1K3zZK8+194hKAXmdkoy6/kD1RMx98g6rwgK+VqfH44M8
         REJ6gS17Jq/SHpFyVijEvU6CY4vQMyWUWqNTy5xduf6cUCVmyQPfk09h8S7/8a1mD7C3
         YdMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194063; x=1755798863;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k6CAcuKvUP6OiRZwfaNhYtqjYVrmxAOs847eh1pJWwM=;
        b=TXyQSqn/mta6Tbjqh/XsP6ZApNR11YxzpnHLLuneYgnu1l9o/Vfl2TXKwXCYutbGK8
         2PzFAFAvUzvwaYN2sbs3Gnyeh8OhD1Lvq4JrDuJM17ZATtpdWoxumtdKwpunuzbZoZNS
         V7Qga6Cnw8enziWfwtqnLk4/ummMkuagIIP+ZnnmolY1bvB3wq+a604F+0G9FtFYrxlP
         WMSzM9lwJAMYZvwDDFd2Th5fjXBGjzoyTDQ36VQRF/6TwThQLCe4priYWR0538XJzgsb
         4OkiS0lh0XWa6FK4nFmMQwpuSY/oHUfbqRkmOD0ICXTEwOanVUpuzyLBswG5xFeQ26+5
         OjAA==
X-Forwarded-Encrypted: i=2; AJvYcCUxOvHdEGM+4uo94QBCD5qpu8kGBZrq9VXpArftF470vGd6Ts57k3Y/aZeksnAeQJDjI318PQ==@lfdr.de
X-Gm-Message-State: AOJu0YzRCDelbX2ZSXPic4rDOajTv7YDXfbEy1LeV/mTsc3PFK/hTFE8
	O/wPl5+0s6xu1gfDxEttLV7YOjOoyrKxbA40DVa8jmEsU7Xa2lmw9yXX
X-Google-Smtp-Source: AGHT+IE3xOzVPLjme0K9m/v0EIN8WpGfZA3BqlYQq95CYvDxHmRfjCgvitmgKxhLeG9jwEh5oj6qHg==
X-Received: by 2002:a17:903:230a:b0:240:11ba:3842 with SMTP id d9443c01a7336-244586bf65fmr62190905ad.35.1755194062908;
        Thu, 14 Aug 2025 10:54:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfmY3S95koEMJgCXHwTMoWd8giEc0rBX52n3Gmj0Owdhg==
Received: by 2002:a17:90b:4a8c:b0:311:cc50:50a7 with SMTP id
 98e67ed59e1d1-3232669fa96ls1419149a91.2.-pod-prod-03-us; Thu, 14 Aug 2025
 10:54:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWr0bECraNLc8rLyc3gYKBok2JShUH3H8ZkYIc4M/krLMqyqgLM6IPsawgKzF45vGfyLNVjZTVHaD8=@googlegroups.com
X-Received: by 2002:a17:90b:3a45:b0:31f:1757:f9f4 with SMTP id 98e67ed59e1d1-32327a864d1mr6597059a91.24.1755194061279;
        Thu, 14 Aug 2025 10:54:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194061; cv=none;
        d=google.com; s=arc-20240605;
        b=GMxLbItFWHgzmr2+iSlyi1xvisaz+hpGxBbPxX6Il7w1ZtF5GlU4fUHYTzwSq37lCq
         EyAm29VwV+QExcfGGzsvjD2kUDy55SENbULd9aa83JkACZzMfZ5mZoTBSu4vURYX3/FR
         fn4qosd3pbDfbYtMB8oEpiIEif/RPuGkARjltgR/uJUXq7xaa+EKLNe9FlSWEFKvjlds
         CtXXiWrCOmClwLNqslSPw1ctQPGB8z8hWCxiwHlXZMb5LPxlr1nJWM9ISNrTi2LfFORW
         oVsbLuIbzlyqVhGjPg7A0oGyv/mf3tmDgL9+orroKweDL8UM14FKHnDL3lOhDnluZd/N
         E/yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sZJR9LA3kgzyZhuFGCo8URPbUfbHRYhrLJioDHKhIRA=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=Wy68a3YyRY30XQpY3l/7oFu+rR2Mscm+jNl277W0tkHqe4tTJ9DhLV2QRjMG3Oq709
         6GcDiobL8y+tPGpb8hVLfP4SpYB0oRBxUwdbpMXhl1RUjBEoJf5GXljTH7+Z4CDOKv2Z
         o2jWYxUjUmr2lD1FXjlhhtPiTJsfEzkbAkfPFtsrBuA6m9IKK06Ycm184PEF/o3vdE10
         dUirVGfNHHH6fR8RJ/1e69/EY6tIPV8sSZd4I1ARvjbtQx/OZdE8SyLenX/e3IZ0Sfhp
         yPNoIDtDjTBpeHZjk2W/zkiWUa9MenWqIlmwcO9RQiGRBKdbRjzZYL6htdQbg/bZdr8c
         CJKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=S9amqurf;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32330f3d7f8si93274a91.1.2025.08.14.10.54.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:54:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 880095C71A2;
	Thu, 14 Aug 2025 17:54:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 84294C4CEED;
	Thu, 14 Aug 2025 17:54:19 +0000 (UTC)
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
Subject: [PATCH v3 01/16] dma-mapping: introduce new DMA attribute to indicate MMIO memory
Date: Thu, 14 Aug 2025 20:53:52 +0300
Message-ID: <08e044a00a872932e106f7e27449a8eab2690dbc.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=S9amqurf;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/08e044a00a872932e106f7e27449a8eab2690dbc.1755193625.git.leon%40kernel.org.
