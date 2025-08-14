Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB2GF7DCAMGQEFQLCJNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 41DD7B26E13
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:54:50 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-61bd4ae12a6sf1906024eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:54:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194089; cv=pass;
        d=google.com; s=arc-20240605;
        b=J+chMde5CSF+vnBSojmRtpkK4amwZTBMddAROf2J7t6Ka0fsb8wJOxGIDzayp3K9lJ
         mjX3b4q514cOnPOwQMcHOUfeoLXXgVccOs/FxmaJn3YRtMGbm2iJTmb1F8mD3xHV95xE
         SpGx/vA1qmirq46aCceDBGPwptDoJljkh1PwyQqW0lJcxb1KgwzEr1FLGANTNsXDhO9l
         Ehj/5A2hWNQvitDUDBgvbGUKZc/W1mFQLwlvk/dYZ1TKUTN2ardpW3AWynyv0w+Uy1ys
         sZTry2tRtJzv+R1eP2aQrUtk/CrFCu/m+dmEb9YHwSmmNrbwyGwSMkbg5OWqPpcy0J3S
         rdcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=uyNjzssqwn2jBs+zDfoQep4VE0kWVb4YrN4XzqFCICI=;
        fh=V+K2YFoqOnJcft2O5VvAbeHSAA6o3ArVTYHlaHLULSk=;
        b=GzAddwQTKuX2AjoVPNSqO43xMe7RZ+yU7Jr/vGOxNuAE2LMO2yvIapk5nJKR01BwxE
         VLgEPuHtJcXGDFwW8DQT4vnOcWOi879KWcwbG0cnAVL4CCCdvJpkIb9zCamT3d2iFN0c
         EdTGkGRlTj09WQUIxhJYt1heV1+q6W0jvN46n70q96958dlYiHav0Tx2aeTivFfyOWZ3
         J3YhN8IJ39rAq8nIq+AH0adOiu8G2JyPhrZ0VG9S2XJ0JuwJFDOJlDOYO2qaHoDCFIjL
         eHUTi+8FZlnMFg0Kj7gQq+EizB8RpMG4Y3jD5uDcbVd6NHTQKPuO8NxjtSEGjS/u4YFC
         7H2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=C6w4ugQY;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194089; x=1755798889; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=uyNjzssqwn2jBs+zDfoQep4VE0kWVb4YrN4XzqFCICI=;
        b=KUqH/QFVdEqp63ddYWqtZLkhdqwrBqx8QbK+WtCjVqq1TXVrYL++/tqqn6MHpvbptw
         8kuDkoRdaTje99X0OBMm8Swguy9Ntxgu9fh4iyYXYVwLCS623z6VQzdaHzJEijEBlhS8
         dwSBWd6/htCK0RB/+Uqy4py97aGGHN4ObEfbcmXdEp3NtTANU+jUW5Cdp55ApuKWIT1i
         kytv3vpQDNyGUy75jDgU9EYMGEidjWc/pvscbhcdbFhMYgRWo90uK5gvxFgrhU8lYbxe
         /diO604Ac32jCRhLcBLpUibjaYKHqfasdbCt+yXs2jsMvjFKF8qx7n3hwPqof6DjMNPu
         Oaew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194089; x=1755798889;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uyNjzssqwn2jBs+zDfoQep4VE0kWVb4YrN4XzqFCICI=;
        b=Ckr3KkcRZz1fjje+T200VEo1UuUdxsb92HQNaL4lPA4lWL4asRtymm50aOfljGcFii
         Ya+4eciw6VJLdDMk6IIcijuYWQXSOz+9rzmWvXkPEkm2bCI3UKt2ZsqIvVvrZRq2SbKz
         RQBgxtSMj9VaN8fYFJS2wvloiWtl5qlcEO+SoBD29xF5rZpTaUjSO3lGt/LfjbFpZa/r
         Gc4HbE/5gUThinks61lNYjJJIdPSsN2NSssg/tXAcHwV2W8rCJ3z0YDnqlLH6i3Oisrq
         xRZdIlkJbTnc7cEMTsJWsUCcPcrIt7q9TdpKPKR/X1s+9ST08wAlmofvhzpli0s1niLO
         4ydQ==
X-Forwarded-Encrypted: i=2; AJvYcCXzSYRPFqmQ7kgJe5O5sPhn0B8HxH7Rx93mC7t6AL9V07Wmq9KBXvsQbLW7xjXYMMjJAzcntw==@lfdr.de
X-Gm-Message-State: AOJu0YxCG1EVw23Oh7hvhj37ixuopbvZ8doq8aNLdR7fKCay0Ir4ZCau
	DVmOBdnvb9ECr/KIKfQG8Iuvhf4HF3CR0VNY4l/cNm9kssW/rtqqig2M
X-Google-Smtp-Source: AGHT+IFBednNBIFEdFNnGpQWU12Yu2il7+YwDm6muIekS0cmjwtiR0VLzzqyY+5MJPNOM2fTh/GQNw==
X-Received: by 2002:a05:6820:1c8f:b0:611:a921:bfef with SMTP id 006d021491bc7-61bd5c895e8mr2591260eaf.8.1755194088907;
        Thu, 14 Aug 2025 10:54:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfoTXCQBS0eZYyFrIIDWI0fX1OqHqOJ80mq/CbE9lm+Ug==
Received: by 2002:a05:6820:c308:b0:619:96a6:485b with SMTP id
 006d021491bc7-61bd49a8dddls177061eaf.1.-pod-prod-05-us; Thu, 14 Aug 2025
 10:54:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzaIL3qsJ7XndTSYgXAwej4BE7UMG06rFfOQU2/ZLSchw4q69Q/0S5s0sQ/pEogt7iyB3Fln1slP4=@googlegroups.com
X-Received: by 2002:a05:6820:2225:b0:61b:931a:a9a5 with SMTP id 006d021491bc7-61bd5be8289mr2527445eaf.4.1755194087923;
        Thu, 14 Aug 2025 10:54:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194087; cv=none;
        d=google.com; s=arc-20240605;
        b=feDAXbW8O6W7qUF7MrUxgVJvCPn2oSavcEGkjjHf2/ATJnAiLhAuBul+ifCacrLJ1p
         CuPyCE8gzUbZdWwgud0OcU+DYj14eo82Y+40raMyrKulw36mfMmVXsMtLlfU9FqvW8RK
         12ss091kHXvFh9b9Kq98aeI8vToiwa0rCLezlW2IwpAKapfvn+nFHnugK86xjr2QGNcv
         rF/qDc6kUUAfMBU9E5RsAxT9No3dq8k9XV2Hg31Zh8vE3R2GSeq4MSqYTYb+tvKUNwlv
         MbfaHZnHevKYBy2NX8+xplK56k2+R9lW8eCwzxWpsFodGTflwGKtLW7SwYsF+gUX3IeY
         ieSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eUWODOYu7xl20YNi/5H7WavDXD5EiHAIElpuMjzztLk=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=TAn2ye8O0ypX6wE2CDmFndJaEZJM+ZxuGNs+vNgBGCh4bE8ULsRe+l/4Q6E8iaeYgY
         0bPyqm3Fdx6fV7CUXUT6f059YQGTnyy5BLVSI7vZwwz7chKIo6mClXZkEOjzNYjjIqvc
         /gyUM54ZsYhJCyHC+FWCpKwEAQuKVLt0hTPtwDH6NNaJGeIirBn82ILOtn7D64TvmjLG
         N8BMVnnueaFPcxJlEBjhbvzlfdPABnkHbRbLCrlzjObyShQudsGqAYLObzrTryoj2HxU
         4D7VdD5z+uC/MBX+xJtOmuwClRVfxM3XLt9qPRlSSGod2iafHTkKc4F79LQmna5a3lb1
         pFVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=C6w4ugQY;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61b7c9a44e7si149021eaf.2.2025.08.14.10.54.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:54:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id AD63A5C721E;
	Thu, 14 Aug 2025 17:54:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8F749C4CEF6;
	Thu, 14 Aug 2025 17:54:46 +0000 (UTC)
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
Subject: [PATCH v3 09/16] dma-mapping: handle MMIO flow in dma_map|unmap_page
Date: Thu, 14 Aug 2025 20:54:00 +0300
Message-ID: <ae473ed08a384bd70e3816cc74e11513213d71f4.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=C6w4ugQY;       spf=pass
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

Extend base DMA page API to handle MMIO flow and follow
existing dma_map_resource() implementation to rely on dma_map_direct()
only to take DMA direct path.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 kernel/dma/mapping.c | 26 +++++++++++++++++++++-----
 1 file changed, 21 insertions(+), 5 deletions(-)

diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 891e1fc3e582..fdabfdaeff1d 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -158,6 +158,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
 	phys_addr_t phys = page_to_phys(page) + offset;
+	bool is_mmio = attrs & DMA_ATTR_MMIO;
 	dma_addr_t addr;
 
 	BUG_ON(!valid_dma_direction(dir));
@@ -166,14 +167,25 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		return DMA_MAPPING_ERROR;
 
 	if (dma_map_direct(dev, ops) ||
-	    arch_dma_map_phys_direct(dev, phys + size))
+	    (!is_mmio && arch_dma_map_phys_direct(dev, phys + size)))
 		addr = dma_direct_map_phys(dev, phys, size, dir, attrs);
 	else if (use_dma_iommu(dev))
 		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
-	else
+	else if (is_mmio) {
+		if (!ops->map_resource)
+			return DMA_MAPPING_ERROR;
+
+		addr = ops->map_resource(dev, phys, size, dir, attrs);
+	} else {
+		/*
+		 * The dma_ops API contract for ops->map_page() requires
+		 * kmappable memory, while ops->map_resource() does not.
+		 */
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
+	}
 
-	kmsan_handle_dma(phys, size, dir);
+	if (!is_mmio)
+		kmsan_handle_dma(phys, size, dir);
 	trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
 	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
 
@@ -185,14 +197,18 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 		enum dma_data_direction dir, unsigned long attrs)
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
+	bool is_mmio = attrs & DMA_ATTR_MMIO;
 
 	BUG_ON(!valid_dma_direction(dir));
 	if (dma_map_direct(dev, ops) ||
-	    arch_dma_unmap_phys_direct(dev, addr + size))
+	    (!is_mmio && arch_dma_unmap_phys_direct(dev, addr + size)))
 		dma_direct_unmap_phys(dev, addr, size, dir, attrs);
 	else if (use_dma_iommu(dev))
 		iommu_dma_unmap_phys(dev, addr, size, dir, attrs);
-	else
+	else if (is_mmio) {
+		if (ops->unmap_resource)
+			ops->unmap_resource(dev, addr, size, dir, attrs);
+	} else
 		ops->unmap_page(dev, addr, size, dir, attrs);
 	trace_dma_unmap_phys(dev, addr, size, dir, attrs);
 	debug_dma_unmap_phys(dev, addr, size, dir);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ae473ed08a384bd70e3816cc74e11513213d71f4.1755193625.git.leon%40kernel.org.
