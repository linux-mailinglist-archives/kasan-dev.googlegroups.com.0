Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB46VYLCAMGQESWPTEAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id AC016B1A1A5
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:43:47 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-7073a52a800sf77733846d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:43:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311411; cv=pass;
        d=google.com; s=arc-20240605;
        b=io6JXV2/i5j5xnRdp6urCZjNq0sQcFZD1CJMlXvOjeY1mXgP22ZANH4ptKpIl9VRpn
         39FVSpCY6KiB4gdwj/ybYQWUgxs9ck0vFdNhuOnmYGm6N8nxXvQp3qZ3c+hPRExWUnaD
         UGN37+XnQate7dPAyYjN/Zsj3IZhbxCNbhJ2Xs0TufAjTmsjK+auoJeP1pCdemHhojHu
         LFu6gtUlrD8xlxahs7GsMo0mkxnsGk7Ua9RZA8rdk0skl980Y+maPl0dsKntoyfRGxKm
         5klDBmEj+Q3kFeenF+Q/c1D1tlygYweaJvu/HSiHDnwppA3S49ExOCXKjQFJ1xjOGwQN
         +dVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=AeXjO8WgGbwDeLPnMCuUyCqfPwVE26R7SHJbzsW6puQ=;
        fh=Gg5r+9GmXrIjMcFeP53BLQ2UArm57C+PqajkiJciFG0=;
        b=Hf5r5x4xO1BTbAv4Lha07U+Y2r1Z0H+1DiNBESlGqpsUhPBd8Y3dza4yYQLY/mx8Lh
         seQthSMY4r/54fF5qFBwKahACoOenRdv9xvfeLSFQdWaFd66GCfwTfOfPyohMTlybCVM
         0O9obscvpZyS/hxtseXxk3CqQZ1pHRbxgCDhBOoaZT5//V8h4XLrjk4B15UVFsDu6Ud2
         a76M8W4B1lq64FaAEBdSemTY+3CwCIQ3GYY3toTdBRMl6MPEwLQxLWoY5vueFVYWkm4V
         XdXUrQzkUfIQUP9Nsv1TWn+4AZla/CS+u30wdV+bTanvd4fK3LYSH25xj9eQl3wFaJrN
         T6qw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mACwCJwn;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311411; x=1754916211; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AeXjO8WgGbwDeLPnMCuUyCqfPwVE26R7SHJbzsW6puQ=;
        b=bge/BSBF6M5WHpF7pW3T4JM+BHG3NXrKHNe+7rzR8PpFwXPWARxx7PLhcP5CZ4i4jJ
         P5RNNk/Aj31NW/q6+/vzCYup5DxwrP4gcXrN/MxMydV+/I7FfbhY1VKoIHDaQII31kxe
         6SEeHG9Q2G7jX2esDHZrDWU7klAw6nSjKFwUntkFKk4ez1vNiZzilQF020YFKLOp2kRG
         WoTJoebMH/n2WgJmuSRiRjdsNEKf9hGeLFm6Nsf7WgLnaYHjo4Fj8BoYjmCbwdLDJ77i
         Bphpa1tuL5v+L/Ycz8uNJoC5F8j5hyWZRbzgs0xufIvZuKl9Uvt2PvmZk4Cy+HlWUJTd
         Bo9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311411; x=1754916211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AeXjO8WgGbwDeLPnMCuUyCqfPwVE26R7SHJbzsW6puQ=;
        b=M5gs2SjGjUziRYpPwEIZ6pGviNdHQ0xvqmU3kUuINFeMnLjKqi524Ii1rekQwGN+6w
         ctF2nd13Q9R3J/S3/aHtlhLpzNpcNlHDLjHCA5wWvNhvyRo0HcOSx6+88FwcjlJixKCz
         ffFVKhUMPGRM0V1e2dSlOIu4LZmERpdYZiFJoWSN2sZO7f1adC1Ln+Q4/0hJk/DMRzWy
         6hqQW4odS5r5s0Mn2H15DrvBUFsiw4v+9SA3YVu4nbM9F91Kuc4zyaNL9q81u0xOikVh
         c7KIzfaKS3g+5ObyKuQ6hSa43xYqExS3btxKH9FX4VYSRn4ZH+MWKA3xvFrQhb+T3z8K
         daIg==
X-Forwarded-Encrypted: i=2; AJvYcCXKnzaeziDGYSWSbHTQl07XBejWcbG8PSHrUWUBpMwiwZp2ZnSpTQ8xkerDMF1gvB4aTouDLg==@lfdr.de
X-Gm-Message-State: AOJu0Yz25kELPc8Z/KpZMPdoIodWkpC0f0MWSHaZXLIeG0NuSyeUaPgu
	Uz+x8dydf5mI9rQNz2lJklISzAYN6rK+8OY+WWFWtwdGdzxQOHy28Pi6
X-Google-Smtp-Source: AGHT+IF6lhSvzbCQpR0XGi+dkxY6rCcZZ/j35hNqskRQhpFXLk9CI1qD/REDhwkoqgyiQo2IX389ew==
X-Received: by 2002:ad4:5fc5:0:b0:707:60ca:7ee1 with SMTP id 6a1803df08f44-7093626d249mr144161586d6.25.1754311411356;
        Mon, 04 Aug 2025 05:43:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfXfSGfaaByODL62sf/lw/SbFUb7aAISBGtPdHSlQxyVA==
Received: by 2002:a05:6214:27ed:b0:707:56ac:be5b with SMTP id
 6a1803df08f44-70778d6f6c6ls76825276d6.1.-pod-prod-02-us; Mon, 04 Aug 2025
 05:43:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjgObx+boKlYXXnsPR9namZh7bYTtmLBDKS3ftErisCNbADiiTuN6MNY7D58emDIsmvXN+9rAYXsw=@googlegroups.com
X-Received: by 2002:ad4:5aa4:0:b0:707:3c59:337a with SMTP id 6a1803df08f44-70935f37280mr120371316d6.4.1754311409960;
        Mon, 04 Aug 2025 05:43:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311409; cv=none;
        d=google.com; s=arc-20240605;
        b=eJeDpVkx8EQgBlRLg5W6afDiILUfN3MvpgxUAwz3w781U4qyzGsOQPYvYQqXBwuKBF
         vgsLpet+fZuFdkS7zMcPdGWnwhLtzjcYAB9gwZfz7iWPznrhcEcBz4I3Voz2xohd7T1Q
         R91+Mz76JnkAqzzybi68jktJleK8SU6JKgwXBJDF2KLWlKKDf1aH4buNKeLpEoavCpq9
         U7OgjtJsFYyJw7vXB7v6/5ivcGXG+dWAFZguZ2qgP7hBDyGqTFfOvLLWjVVwq9HesYzM
         UqVMvQQfmfX1bUqKj2eQ2OoSon8vAYhB0QP5iYdXa3v6QuSZOWtH5PMAY/xFwUi50f93
         GVfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=f/3vSq9381IaXbqW9OZrKrqA9rxmKdWI6yV8YceURS0=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=aCjGaL75jqJraWVe3P+jsapYskB6YJJpfNB3U6/pZJkfbtgrhYb6kqk7OPt0YvIpcy
         +LH6QwDQTLE2NbE0x+xGOITpPl/dMKi1Ji//USA/zpMmofSi/5cIu2HO2MSUMx2DFONb
         ET7FdG7IVeLZuflOqBZCr5wR+b0Wh+3FG7K5aEnJ+W8Ed2XSZ6XeBcHYu60LFQPtgf/Z
         3EG8qvIgB6oYtbjmuYYFzF7iChqT7UYTDvRunJchuK4nQI1qYKi8HpbCPGz/ajrBOU4+
         QzQwdgnkgrkmJFEQSpq2RCR6wMCTzI5bKeo29LYkLhCjy2xNn6UviuoIDBj0MeGA9b2I
         GYqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mACwCJwn;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7077c95ddefsi4168406d6.7.2025.08.04.05.43.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:43:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 28A9644938;
	Mon,  4 Aug 2025 12:43:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 96668C4CEF8;
	Mon,  4 Aug 2025 12:43:27 +0000 (UTC)
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
Subject: [PATCH v1 01/16] dma-mapping: introduce new DMA attribute to indicate MMIO memory
Date: Mon,  4 Aug 2025 15:42:35 +0300
Message-ID: <f749c597980592ecc7aeb5ecca974c8dfb76f834.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mACwCJwn;       spf=pass
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

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 Documentation/core-api/dma-attributes.rst |  7 +++++++
 include/linux/dma-mapping.h               | 14 ++++++++++++++
 include/trace/events/dma.h                |  3 ++-
 rust/kernel/dma.rs                        |  3 +++
 4 files changed, 26 insertions(+), 1 deletion(-)

diff --git a/Documentation/core-api/dma-attributes.rst b/Documentation/core-api/dma-attributes.rst
index 1887d92e8e926..91acd2684e506 100644
--- a/Documentation/core-api/dma-attributes.rst
+++ b/Documentation/core-api/dma-attributes.rst
@@ -130,3 +130,10 @@ accesses to DMA buffers in both privileged "supervisor" and unprivileged
 subsystem that the buffer is fully accessible at the elevated privilege
 level (and ideally inaccessible or at least read-only at the
 lesser-privileged levels).
+
+DMA_ATTR_MMIO
+-------------
+
+This attribute is especially useful for exporting device memory to other
+devices for DMA without CPU involvement, and avoids unnecessary or
+potentially detrimental CPU cache maintenance calls.
diff --git a/include/linux/dma-mapping.h b/include/linux/dma-mapping.h
index 55c03e5fe8cb3..afc89835c7457 100644
--- a/include/linux/dma-mapping.h
+++ b/include/linux/dma-mapping.h
@@ -58,6 +58,20 @@
  */
 #define DMA_ATTR_PRIVILEGED		(1UL << 9)
 
+/*
+ * DMA_ATTR_MMIO - Indicates memory-mapped I/O (MMIO) region for DMA mapping
+ *
+ * This attribute is used for MMIO memory regions that are exposed through
+ * the host bridge and are accessible for peer-to-peer (P2P) DMA. Memory
+ * marked with this attribute is not system RAM and may represent device
+ * BAR windows or peer-exposed memory.
+ *
+ * Typical usage is for mapping hardware memory BARs or exporting device
+ * memory to other devices for DMA without involving main system RAM.
+ * The attribute guarantees no CPU cache maintenance calls will be made.
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
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f749c597980592ecc7aeb5ecca974c8dfb76f834.1754292567.git.leon%40kernel.org.
