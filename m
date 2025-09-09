Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB5OWQDDAMGQELM7GRQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 8170CB4FCC2
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:28:23 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4b5fbf0388esf46727141cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:28:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424502; cv=pass;
        d=google.com; s=arc-20240605;
        b=UxTdzVj1Sj+xtWg8Fuiq8d9hN6pQouDAe0zIHd78/6OfmVINEB34vD8i1xYxhKE6DV
         6V9LC10ggqs/bTtkRUYPBlwg0Lze2NZWRkpGzB7tkaz6M+jWwoWQhuslCKOy/CjwtyXv
         oWCz5fMfnrgV8D5DQfcAMmMdx64vLTTXl43UDcevIDjEs0y+iU121eANvX66RjEKLA+f
         6iJ7K8kCXgy+6HIhJlUC7LQ8nqo7j+40p9AGVUmRhDyr+kOPS9ttYkUVsS+BKnuvj5cV
         M9O/vTJUJU1Iptyrofv9clj55MRU19S9RVtRmRO+54FE1ilyM/nPP3Xn1SgYMQHSpX1B
         0fOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=PopaBwMWtcDUeAJG9VXxTFMYUSZYzQJf8BiHkqetbAc=;
        fh=K4JxMpMAjL/BQGQi8cPmwru2wwVZnBAQrJtEXaWHYIQ=;
        b=WAVvX7LzYpASvsigVofcT181k4p5pvUWmP+zTsZ0dyzDYLlV20OtdufX+fBLRQj9Jl
         Kt5nePTeBt4l3OUiWrZLXK5qlYtxYgR3v0lO89+i4LgWLG9mQIPeMOtJ/AgS5yG9semb
         kyhMbq7adMx9zfH0yuSojcR8EBLeUzYwKE07uXakSaYSB20FpLNffhc/DhbuuWL9qIUH
         fZWy5N7kamzfzIXH5Xw++cw+V12tbzRxuN9MAFToidxS5YOa/aFfWkKiN1ElAKD04I0F
         fMyHjc6NvxkvPviPYgvRnMqA3WiL16mv+Mlw8xYFuKgORECScd48O+iMD7G5p/is3wd1
         sYlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=W2fAXIdM;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424502; x=1758029302; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PopaBwMWtcDUeAJG9VXxTFMYUSZYzQJf8BiHkqetbAc=;
        b=TobEGTDIjkiPVYQFDLKCQwx9SSpFRxJgkIe+Tr0DWyy8hz9AfPPYQvwh27SXC46ziL
         V79dONPCiwNPVNdBiGCRPRDC5LGZCkGsTIC70ncsyCDebW1ci7parb1mtG+irOvTMZ1l
         dXJclHEgaYM0cE79t41/Mph8MO7sNFIvIvSTtxQ7jF1w+HuGp2xAho4PGnFUFf67E/VI
         EseU7jFcSFxQ40i2A4ZdJP+6KBk6svtyF7ZQDLJ9SEubSnhwz8/3bHbSp++NcVpEXH8v
         9BfoXQPDLEKUBqy/f/zdhmKkcFRJnBdR1OMI258/YiNBqint2mLc9WuJb8jhWtzOtWgS
         NZhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424502; x=1758029302;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PopaBwMWtcDUeAJG9VXxTFMYUSZYzQJf8BiHkqetbAc=;
        b=ocpUTS2R4MNiqiFzoIhVmhlpRFpmtj8MP+5IkCQAQvIcC2LWcb7cqrFuQPz9hfn5o+
         78i9NgFMd8r+cSeyWelGnK4KlyvoASMkJdStKcqkmnpqGYM8d/mv1Nbifi4YDJ563fB8
         uVbUlZlBc6Xp6ISzky/ak8xEr48w5GUmYcDhdeAjPEvYjqPFpPnI6aaWEInozUvEMdUk
         MRfch16HTSwt+Vz5MzZo5Q5bWxU2NjO7acZuWSF35NZrvfhkLO/6qSaA2fe8T+6sgnlz
         mkLVXW2cSr7xGZSzsQ+k4bZM/BO6WDpgj5u+pwDF6JRWSOk3W0A0pHj6nNi6RzT2iqoX
         eZ2Q==
X-Forwarded-Encrypted: i=2; AJvYcCUlds5gjy2F44gO3Bf/QlrWMdfKdczdYz4b5roQ6DS5L46cLclI1n7vArc7eA4+P+37ykasxg==@lfdr.de
X-Gm-Message-State: AOJu0Yy1TnNIm6SnOe2dPyU6u0Ltcdoxj8kCSxpoqh8zy5WXNoGI85lA
	nMi+X0CYl5Frl4R6kCgPdBJW2bozUfiRCTjMtCflY64ry6d6jdTQx50m
X-Google-Smtp-Source: AGHT+IGU0awt85+c8nKZI+Tu3QWAonv/EEh4IXoOg733cBVWHJMbNKPyfNpzliMy+CxYS1CJeYMDPA==
X-Received: by 2002:ac8:5f06:0:b0:4b5:dc7c:a6ef with SMTP id d75a77b69052e-4b5f8426159mr141168191cf.50.1757424502171;
        Tue, 09 Sep 2025 06:28:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcvc9ZmhDQGQmuZITdgwgvxFJERuZSZMEP/gWSu4Cefdw==
Received: by 2002:ac8:580b:0:b0:4a8:17dc:d1ee with SMTP id d75a77b69052e-4b5ea7fbb73ls76085421cf.0.-pod-prod-08-us;
 Tue, 09 Sep 2025 06:28:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWD3vyTYuN+Vj0mCy/GWpaYbR8pVnNeOhymzFI7guaU53ZQ9Wc/0AQc/hazPYDf53OG88DaYYnPbFw=@googlegroups.com
X-Received: by 2002:a05:620a:701a:b0:7e3:4416:fd5 with SMTP id af79cd13be357-813c38ab5b0mr1217578885a.60.1757424501053;
        Tue, 09 Sep 2025 06:28:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424501; cv=none;
        d=google.com; s=arc-20240605;
        b=BFBbsEJjJKPZD6t6MGQpZ1ULPPsr8ljrDGsQINxJ8IDjUHCSjUONA24zq+PJh4pbQE
         RukOwQY8MOOyWTw6F1fu2jEX2enbyScCQDPQ4MRNah4nrg4QjNiYXwNrXi3BaouqqQec
         byjCD4LVWLGGNyJ1fODRbn5GhgKkR+/KR06isDsw3yhtJIRaH9sZ22oAmkrrn+C68VAh
         Lbcadx+7fblssCWfZvEPaYHtbricchARPYyQ9K+n6+ZdUKtu+xpUDCycqsa9ubn8saDv
         p0/1DSxsd4LqWeDE+JxRedQZM4f4U3K7qlC6NyYLk48od1AmwcyLEaqCE5u4h9zpw0eq
         n7Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TaOMXIJ/xNUUto3Ykfack/WiEZfO7Ok8iMVsFthoJCo=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=bQhLeoRsG7m+6uq3qiCziOfwCc5dXYcC/Te3a4zXWkmtE1QNTN2a4tojW6kVZnkgiL
         7YZ/AdPPn91zBc1NYqZFTj63thrTCEqLrJcETqp7uDdcp0bAhqPM/uO2pbI1WLijXRI6
         /WY5iiZ1aEbMxjNOVOAzalKDfgC2MvPec4EBvg7usCtKKYX6JClkxo/5MlBMpy1CS5PS
         t00mN4PmD7b4FLpaPvuSLvzOi0ZkJq5H+EQqBqpyFLquGrCtEl9ilTbsm1EapSixLqOW
         e7oazb5yZfl7fDwIXbS+rzs36LOnmugVM0gKBRZNouvyGmTomiGFsEwklYUe46bc154Y
         YGdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=W2fAXIdM;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-720b14475e0si8015316d6.3.2025.09.09.06.28.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:28:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 4F10844976;
	Tue,  9 Sep 2025 13:28:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7F41DC4CEF4;
	Tue,  9 Sep 2025 13:28:19 +0000 (UTC)
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
Subject: [PATCH v6 01/16] dma-mapping: introduce new DMA attribute to indicate MMIO memory
Date: Tue,  9 Sep 2025 16:27:29 +0300
Message-ID: <6f058ec395c5348014860dbc2eed348c17975843.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=W2fAXIdM;       spf=pass
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
index 1887d92e8e926..0bdc2be65e575 100644
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
index 55c03e5fe8cb3..4254fd9bdf5dd 100644
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
index d8ddc27b6a7c8..ee90d6f1dcf35 100644
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
index 2bc8ab51ec280..61d9eed7a786e 100644
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
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6f058ec395c5348014860dbc2eed348c17975843.1757423202.git.leonro%40nvidia.com.
