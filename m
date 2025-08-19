Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBWPMSLCQMGQEOKXUEAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id D2750B2CAC2
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:37:31 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4b109acac47sf163633061cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:37:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625050; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZB+vO4gEw4gkpkRjY+4G1vX9wqKO4qJ6khouIhq66ovdf5FpkhQ3nbXEdBEuzHPkXm
         rPHex1bUuSX7+PCHP1XOzI05dSCFnogREugf3Tg4ZaKp6FAJRdW7qtI3DJAeW2PCyHTh
         1kXzGBqm/OIceNyEmC/JyHFILFWtBAZyPQiFS64rpQU7Lv7cdOju4DWdc96ywuPTIKR0
         2s3/MEVwlceDshirZMFBtR97uM4IZxNc0Q8y4+vW5CZ3g1CZVaOgHVBzu0lC8MRBjrUo
         N3k/io6/RaoKngf4RZb5OBPcI7LnlM3+XFqqWgqE/emKFDLjV1z6YMB9Onm1rsQzyppw
         vonw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+yuNSDi5mVzBS3u2tCADq/hIWPN7NyKlAD6A7ugehYk=;
        fh=jaVdpC0rSxDoxn5ihfTVI2sFvqOh6SSFKk6giD6y7Es=;
        b=ANz8v2feMNtbqcz61hcv1iRa8ztpa1p+9SMlKgVyfJot3WBIFMp+X7E30Sqkdb+A1f
         JqVcmfPEeWFz+WXHMD5fNwYRYiTdn+oUEIsp7FktEvbCjt5ur7/8GLaD5CLG4zdrvyjR
         8ufJMmAM4JVcL17s3XP1ecISWroelBJdQEXRwGS1/vs2f+1wCMCfj5D5GFCZsgQ+lXAD
         7hePhG1QT/WvW5XK4RalJfbuuawYDTSL+Y6IKckux2gUZU3BeKu4Q9kmY00bBGwjj+hp
         JPj+TKwTPaqexEeh5XsRbNTfGUptPp4D493obxw+6gmLs2L66s0f71qnAU1xzBaok+KD
         t4ng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kgbi4w2Q;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625050; x=1756229850; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+yuNSDi5mVzBS3u2tCADq/hIWPN7NyKlAD6A7ugehYk=;
        b=P679Nqf4gj4jxqcCiYX4+lk8sCPd5E06VAU9Zk2PyGX8a71YBYWV1EsC6+mhgf/3uK
         aa4IzxRfwnFwEXlrwY9+AyhAjKD/zEQoYURzHUBmBSStMjkHDq3FL7f6XrHPWUA8NcIH
         cAd1uFzybVonTI/OZ52r4vlt7oxPVIbZCQHTHS24W4IoP/WBm1Mru+aMktaY5v8LsnkU
         7tnY8zaTclk/8/ricSBOlMk05BXCRnGukbuT0Dk0BTUpRQ12XYz1A0IGJwH/ddlRMnqF
         iUp/IJdL9ns3xqJEzA3Ufs2HUfjhhyLx4+JdtRugcKyrYrkEkGojh3vEAGCczIA3Nsx3
         PQyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625050; x=1756229850;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+yuNSDi5mVzBS3u2tCADq/hIWPN7NyKlAD6A7ugehYk=;
        b=Ejl8vTR3jf9Mfz64WQRZo5cKrw2I+e+jQvNnytmILAggnaWR+uMLHS07cz+3x+4Y2e
         UMUHMfP8MpZqP+1DOjd8F9h5PYRSfc4Nw0n1Fk4zAOQrithom9GcTEW6t16Y1jwaH7vA
         XhetewJ03k3s6KASUZFcApFVSvEC6Sz3gRLOpEEFMr7JkMz0SmfilBve1tP3K1HMYHH+
         lK+5kobEVd2ZKvZDGpCNiIO1wIBzb7hULLQuuMbrb0MBbTzOHer0tyCUk3laSH3hOUGO
         vAcAeyi8yShGCNbZE9m5xBbk1uPnWlcBlg/FGCR2av5Qx9AezwRVRT+3SOg9Ae7cSNmG
         Nsaw==
X-Forwarded-Encrypted: i=2; AJvYcCXbcS22DcgZPMO+SEFG+evf42VGR45Qvnc28Q1coq4he+iPRGeVShe6HeOFxdWEddOnGZho3A==@lfdr.de
X-Gm-Message-State: AOJu0Ywd3e6pG/ofWlaNLnDapnraD8ZhvJe2UnKTGBjhyzUBr8yA7Riu
	M7FAIgi2JPSxbWmNzG88HX7oOiWRkDV3i6GzZvEr/xDL1aH+iRL5YTra
X-Google-Smtp-Source: AGHT+IFN506OnPjlmkvdtAIEtPXSXoiTodR54cAtSB4qYOXo6lxT7ks6eulfiwI2dRzFYwh8x6UFjw==
X-Received: by 2002:ac8:7fc1:0:b0:4b0:6836:6efa with SMTP id d75a77b69052e-4b286c6d43cmr37420631cf.17.1755625050333;
        Tue, 19 Aug 2025 10:37:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcZUXMfoGUJzY8W2S3awdlyV8WWFHZiE2a5N85a/5Vagw==
Received: by 2002:a05:622a:1a16:b0:4ab:825d:60e7 with SMTP id
 d75a77b69052e-4b109c35fa1ls93935221cf.2.-pod-prod-01-us; Tue, 19 Aug 2025
 10:37:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV+zMJgT2r42g3YuCBtZUbEmTKYa0dkQgYa1UJdEk9WanSw1U+y4fy2AJaLfGqVJLLsTzEGIRyh/iM=@googlegroups.com
X-Received: by 2002:ac8:5f8b:0:b0:4ae:fcf0:be94 with SMTP id d75a77b69052e-4b286c6e95amr39295971cf.24.1755625049165;
        Tue, 19 Aug 2025 10:37:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625049; cv=none;
        d=google.com; s=arc-20240605;
        b=UsLcWBOzIJicKjA57F7gIf1YEV6Ec1QGrJ8J2p0UET1F3pSBV2emag79OdTSsqcDLe
         xITwbYziw7q8/dHw20ezLi1HUOwclINs506dqApM3aWwWqOllBJp3IZ/4nZlCkWfYAv+
         jXHE0zYwpvqUY3V80VYXniCsf1egB27aYSrut1IHAZHnOXuIu3hZYzpmR/txXNNFsF67
         J+mdcjcSkZMjase9aljs/zcFm04q5Pq9D3pX+Z/oOmKJdzNGrtmtFnLvr3Rp12fXh1ue
         h0cvsVMoesDSkrtkBXiLxwVkR5BgTQ8FEHpTYuFiRfynySnIAltjbWX9vEf8WmEb01sn
         MA0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sZJR9LA3kgzyZhuFGCo8URPbUfbHRYhrLJioDHKhIRA=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=gVO5GNZZxLUyiHDJTRBuirwIbQWY0TaxMl5Mi+pz9HkdIQ19Jp95/B7I8eprMagnZi
         wrj2OQcfCs/Hq4BUDwRvJ6pMPwQZFId1zqC4laZCFxS8B+canlQuN6bueCt1eMjoZfIf
         DMYT3KzvPkxjKKCoZvfbW7wVYiQ03FXhRdaJWf9x3CvyfVn5gi1GR+3/daZUVRJIef6/
         K3+9G2Aze/tC7Bu/wEGxwv2LTL2tFWamdn3/0C1w1tdROUQQ2Co0EbwnPD4GzglUfimD
         ACI0zfYbWnC+tvtw6jhxZ8+Ejw3PNnTAsyt/wPdBmqAVjPlftmTs+TJjY+a2+XsDcnFG
         47SQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kgbi4w2Q;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b11dc83781si4225471cf.2.2025.08.19.10.37.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:37:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 85E345C6338;
	Tue, 19 Aug 2025 17:37:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 24115C4CEF4;
	Tue, 19 Aug 2025 17:37:27 +0000 (UTC)
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
Subject: [PATCH v4 01/16] dma-mapping: introduce new DMA attribute to indicate MMIO memory
Date: Tue, 19 Aug 2025 20:36:45 +0300
Message-ID: <08e044a00a872932e106f7e27449a8eab2690dbc.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kgbi4w2Q;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/08e044a00a872932e106f7e27449a8eab2690dbc.1755624249.git.leon%40kernel.org.
