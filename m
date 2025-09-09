Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBH6XQDDAMGQETCESRMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D074FB4FCE5
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:29:05 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-88c814d2404sf178668639f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:29:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424544; cv=pass;
        d=google.com; s=arc-20240605;
        b=C6ezlrnfEh56W2BdrK0MY7NmxaaX20zdqR55rXTXZ3q9aAohza38D0bXonayL+rzhI
         CNJPwmeQUbcoYlVZg3Y18IsLv1PcVNDYRKNzJno/mH2Imzxm4f+0dVO9/V5N0T0j4k11
         7L++FhFh1jbQz/ajtzKiUffNCayi37BLfh7+ZcFggeRzMZ7c83E2u7eQREEn37NZnpPp
         +NjbEcLgJ3cZ4TUyXxtXaiNAmFhNWQD2oFNPmml0pcFi5ZL5/J2/ug4JC4lHmlEie2Hp
         NA8eoapHa5MVLq/pzL4H8R+XWQEB2ilLhwpCpK9BzBtVELqox6zQZ9tTXn+T4sD3gULS
         naDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZERD20xmSbZrBnBB0yyUaLtS8qp+8BcgHSZFYgpOznM=;
        fh=doGQQE4Biz7Fb5BLFfETKW/JReN2fs+3Foerqc1jOeM=;
        b=kaw6yS81AQ/kdZqTGqfAcE2NFad7dYsMYAaoZA6qWpSCrnAiBYFtqsRhtIWCMy1P0F
         B59+3ZuWxox16JSlhE8yplg6W5QHB6ObpoVeocKIx0nrlHH6FfnWMrRpndLUJu+TQbdo
         CW8/ML9xSB5fG6fBBIGc80ResxgntgTiMjQt1eZdHTLAvvG8BwVRNS0ELtEuC24++6E1
         l7GLHMBAsm9Q9QqSNskU6s9UmiMdAJAQrYVabuOvtbjn6NOFDHTXJijNA/hLp02XxiBz
         QcrIm8jr3r7J+eNuwE3NGh6hEVsh4EA9RXc4cdY3hQWL86k4McRfJ35ak/B5xcGkk0+Y
         lQ7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Yn9O7EXt;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424544; x=1758029344; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZERD20xmSbZrBnBB0yyUaLtS8qp+8BcgHSZFYgpOznM=;
        b=jdPjgKEM9AksB0/OSI5ZeEwQfhbL0wkGjH6n555P1FKH5aG4HfwsZpRTJv+FcUCO2a
         vy9cJeVoS5/rGfLAUvULUfF2pIL4zZ+b3hlZE91MrHwksmZOK9vEJuWujzIaQzaUu3iN
         l1gWXuGXLFFgK7cWIRWmgHI+PNV1TJkRTcMJLHD28fxSuhMRxACfvrVrJrRtDnHKYrRl
         vomb9gX+5GC4ooyoTtfTWFUgIWv6DK/CdhRIKanl1t3pR4WwPggs9pxQD+JtDrQaWWHC
         /PgLTL+C2S/tlP2KZjuodCfGv/fXdjns99W6JFis6QBO4V8wA4IEazkiEhSgDnkTq4FH
         rdwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424544; x=1758029344;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZERD20xmSbZrBnBB0yyUaLtS8qp+8BcgHSZFYgpOznM=;
        b=umz6Xs88zWuZ84Df7+A+RPi18EZvX585+FLVFtno7ymWAi6idPRPzOQMGtlhL+Sz3F
         TPN3wQRubxPB2/Ptfbb8gG++qeYJcEVd+oWFKSlxXAi6cG5r0JfItIgUU91MeaAJsUnz
         1qQMzYR9rhCQnGU+54l3zRwEXy75TD9daKiKpGEZddKWUTaSM+H4LqTDZC5ciKfPm/Rz
         gpIz/ntSvR8v5v96gmdSb0zUirPQnaN1JEDQySD8CoGHYmLERLyy8dWlWgTqLiBlDiQA
         KSwLXAU8TXolJJMbHTtT2ClXTeKNl+5hv+LeOnhOTf72AVWXN85MnqDEwXnvv/MA/VeD
         hA1g==
X-Forwarded-Encrypted: i=2; AJvYcCUCoG4xgISMtLKNUv1K4EIzIvRR8GkzAgvbvawV3j/m01k2OO7aMOjmbGvHfBG4uCl+wPWk7g==@lfdr.de
X-Gm-Message-State: AOJu0YwK4oPfTRh6DOH/FbZ2UCJJY4ditzGxkGACueqIoGnWFMLBQ/B8
	69B3Aww9D22fWwHIVg42ThoKRlH3bLUkXEDEDWSCV7j/eQXCOycDBxuV
X-Google-Smtp-Source: AGHT+IFv28R7LQW/mmBC/EImjeWXSQ/eH+l7AxpooofjdBgIpBacANhqNV+qxtHO0iIQG0oHnb/YQQ==
X-Received: by 2002:a05:6e02:1d86:b0:3fc:7359:a850 with SMTP id e9e14a558f8ab-3fd8811506dmr147554055ab.16.1757424543981;
        Tue, 09 Sep 2025 06:29:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdqmrJ0fLdK2BsClNJD8+gQnWgWigqsr20xST92zsvNYg==
Received: by 2002:a05:6e02:318a:b0:3e5:1b1e:ec7c with SMTP id
 e9e14a558f8ab-40b58532801ls18044625ab.1.-pod-prod-01-us; Tue, 09 Sep 2025
 06:29:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUskwrT3U35XXtDJRnYlChp8qzb5ezVOpWUchdbB95tRmh+Ikg5USBrpP3j8ZA4+kOXQBE4kbFWVP8=@googlegroups.com
X-Received: by 2002:a05:6e02:1a69:b0:3ed:eab:439a with SMTP id e9e14a558f8ab-3fd82164022mr167437625ab.12.1757424542995;
        Tue, 09 Sep 2025 06:29:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424542; cv=none;
        d=google.com; s=arc-20240605;
        b=bzVEbWAwbTyKBKXF2dpmQi314NQGW1NjbBOBRcHfAxIHE99yAAuE1/Y/UXqatnKUrb
         7ZFfclzT37587Ug5Gi4U0xH5LTnmfv4SvPcY44LI7CTxlV+y7TOGyYarpbNu7NLN6F1S
         LQ5vFvjxri1yYg5DsU4KdU+eRxEiz9yUYMu74bRuu8VSrReDwgH+zyBDiOVXleEVz+fw
         /yErxST/hmrXL3uh2jDNOzmmzsQSnK+gEZpxzyu890NeQJCCoCzYThclRYpfYy6jJRXw
         0To7VFI496qZp9bQK+DG+/VF56/1TMojKMxQ3AXE7f9wMblqt3C57LvQ/ySB6vpf9Lbz
         qd4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Wq5tVW5DvJDE81W0cJJf75vfvzKk8m83klZ2MPhgbjo=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=gk/hsXqPU4G/Ub5JsCXdYDCk2C78DdJ/z3D+fvF13aS8bkA8YhxG+kWwdk+FnDGvMT
         quXHxptcSj3tNs6etA6xrGmvhcfxl0fyvRFOqacWB1k5zt6CN81uAspfSOWc0QAhHhHR
         R/pZeerTe3RRN/FHmB6b0QQab9m0AKlX201nPepGx6xYfD86LN8tzM1OhUdv39k9Vh/R
         /BbBD9rTIwj1Ey7x/86l+n+0H/0sxBzuUjfd2ijMoGt6TcBEpu9cWWLME82YRpYk+wcQ
         rO5USv3ZWFbbIAN5wR8ZUO2t0Zg2nWqPPEdLlX6pkYwTeVsPNy/62HhNMpyosBuzsBCx
         LUhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Yn9O7EXt;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-406b652dbedsi1918265ab.0.2025.09.09.06.29.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:29:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 6C5B360230;
	Tue,  9 Sep 2025 13:29:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2DA0AC4CEFB;
	Tue,  9 Sep 2025 13:29:01 +0000 (UTC)
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
Subject: [PATCH v6 09/16] dma-mapping: implement DMA_ATTR_MMIO for dma_(un)map_page_attrs()
Date: Tue,  9 Sep 2025 16:27:37 +0300
Message-ID: <3660e2c78ea409d6c483a215858fb3af52cd0ed3.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Yn9O7EXt;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted
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

Make dma_map_page_attrs() and dma_map_page_attrs() respect
DMA_ATTR_MMIO.

DMA_ATR_MMIO makes the functions behave the same as
dma_(un)map_resource():
 - No swiotlb is possible
 - Legacy dma_ops arches use ops->map_resource()
 - No kmsan
 - No arch_dma_map_phys_direct()

The prior patches have made the internal functions called here
support DMA_ATTR_MMIO.

This is also preparation for turning dma_map_resource() into an inline
calling dma_map_phys(DMA_ATTR_MMIO) to consolidate the flows.

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 kernel/dma/mapping.c | 26 +++++++++++++++++++++-----
 1 file changed, 21 insertions(+), 5 deletions(-)

diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index e47bcf7cc43d7..95eab531e2273 100644
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
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3660e2c78ea409d6c483a215858fb3af52cd0ed3.1757423202.git.leonro%40nvidia.com.
