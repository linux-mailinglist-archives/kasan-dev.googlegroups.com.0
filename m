Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBBUI3TCQMGQEDOLML2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id AC10FB407A4
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:49:44 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70faf8b375csf62095856d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:49:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824583; cv=pass;
        d=google.com; s=arc-20240605;
        b=fy09dWVXsUreInJHyaCxVboWVcqAQcxB9cy6L8lAaODC1xL9P/gaR8mmghMW5zfGfs
         qzu59HjxUpaz55fY2+OTUb5zllS/SkTMJScjITYMKByRtS1yIL9eKarbF6jscAG0fP77
         vL1+gPIFzvmOK9Ntvb22oe7zzjXiUdlVcTr15BgbOMLCPID7WjAxPO8Gu3WVlNCPyX2v
         yymW+c5V/8ECahaup+5Hg+OTfBQv/5W2gp56sVt0rsn3Go8g31tsKPKmRqMnF4uDsXcs
         lGEB+oS1K9RGrPu5P1tW9EE2EbMR/YS+ypaFccvBpx0ydnjpae3tLVNbKVdydQp5Tqmo
         bWMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=e61NoJ/ab3TWKQ24smMm0Fy1PFHMr7/wvwpePRI5ASw=;
        fh=z7tP9UAl9WWPysllvTbEl4NJ6YHqppBIhbbQwPnn14Q=;
        b=bO5Fax0m1MVh7yeqp2Uky0CI6G4YYdjCOXFuySzaLpxsYPTghDBlJGc7mMIPB8G2VW
         8ed4dnM2oL9Q6hsy5LD+8HtgPlcWI0RHpFSP9nfkjl7tXUcgajiXts/sTFZ5NqtUySKn
         BXiHQ8Xgn+POM+ai5M3hdCum33u9R0sDRaq4tThMfoQbf6fseVHDcrj2MBdscly2naeM
         6Dlyx5RRTNGjjptXriLjhj1N/cHSM/dNPujcIV92Bh+Hf0DxbVyByswVZ48qW2/sgTqm
         mij+ri1Cxdl5C/CzcEhp7D553s5RFsqqPGNNMQ8tOzpJF1ZXXUR3rlHB/SlX+6edpBkN
         YFEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JZSrHfV5;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824583; x=1757429383; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=e61NoJ/ab3TWKQ24smMm0Fy1PFHMr7/wvwpePRI5ASw=;
        b=FZ5SVPqi/0B2i7uG7QLa4/+fePQIZqOlVBc5TAxjQ+sFgIjWKk+QqtBSYBhJOC7juT
         YVxPcDGIa/jkBS+37/rYypq2S8J3djV98DgcFgwwo0dYI79K26Mw4OfpoAOVf/Wu9rfI
         BfjAqjOwSiDa15Oyw34rmVJNd7snGM8SRxM3hlZ2eJlwaJLQ8yXHL2avEF6/oqzkN9X7
         GrBTg7bSeOCf4eWT3uBcXvy6kBA92PXzR4+6rEJPxzI6YCRfUuA/efnB6eLN8EyjoYhl
         Z/JmbwNCpJb92uXI6ZyKXGf63YunPsygw3UCgRfVMvhtvXhcnJu25b3ZYd9N3S7xdcb0
         phkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824583; x=1757429383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=e61NoJ/ab3TWKQ24smMm0Fy1PFHMr7/wvwpePRI5ASw=;
        b=MzimubGlbC8vjZppvIs0AhtwnDSXJpcujrfWXn/PqehYN2bkHAz86rnz7HmVQPDgum
         WmwBvYRdSnnFZo9oeBIim7BrgL+/vemnDm3ZN9HPussGORDbrV9EpAMp1Rz49HOH28CJ
         L2AtKNg3vl5gaTrDi5m92aBAFACdgiPJO/U/0brJF6SDS4s0+Z3IVaCe2RzSuXW90/0C
         KJDtjoWB7iuMK1o+cZZdP1SnF7KCTqfxwegT6wY1Xvcf5MTT5psagFiqI8DsXxL8kX6P
         j95EpPC6rOo9hWAZbDJNhEL8AzTC2Q+Nr4BciGohVVh69UQYnq0/cHsCEWy+Moj5Iaq0
         1nlw==
X-Forwarded-Encrypted: i=2; AJvYcCXZ3v8E+WQQWvkwAn0S6tST1kr2Fd1GqDoTWUR5vHHPRw3hH6SGyLYb/JFTHzGgZbnfm2rVPg==@lfdr.de
X-Gm-Message-State: AOJu0YzrLklaziNYWjuYl9o3mt76Nc6txJUp01O3MYNErxBvhxXVZjzm
	tlJeyYjTBcfD+0NCRsKGg7hhFBFO6OIuHtSMtucP9NzRgT8FG64GQwDr
X-Google-Smtp-Source: AGHT+IHDDk7nJAWFdfBcHaUS54II4w7sG3FdN1MW07bfAbaLsQy4xzYLXUU+Rqlf3hKvQD1rrWw55Q==
X-Received: by 2002:a05:6214:19cc:b0:716:ba73:8b72 with SMTP id 6a1803df08f44-716ba738bf2mr113908276d6.19.1756824583122;
        Tue, 02 Sep 2025 07:49:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdY2BoHgKUMsXqy9uLrw0bMHw4y9lXZCj3ba4JUXXesyQ==
Received: by 2002:a05:6214:2267:b0:70d:b7b1:9efb with SMTP id
 6a1803df08f44-70df04ad9a9ls73633216d6.1.-pod-prod-07-us; Tue, 02 Sep 2025
 07:49:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWciZr3S7amyG/ixhpIAVRx+kXtr08FzHhuP62+9LR447SuZNgM8zDFwynWqUOmUFEbSa6mAvcNXtc=@googlegroups.com
X-Received: by 2002:a05:6122:4696:b0:544:9313:8387 with SMTP id 71dfb90a1353d-544a02a8c01mr4167768e0c.15.1756824581348;
        Tue, 02 Sep 2025 07:49:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824581; cv=none;
        d=google.com; s=arc-20240605;
        b=hUkd5mSmdNdPQvgfaWNSr/YZWOqmW7LBS4VEf5jznDpzCfcYkSd0tLu2EsMoBRbihB
         9XigFakWnNGZRP+4K/r507RAWBKtM6mpZnHccyrV/qIZIenx8KGpmJYEr6uGSbcB1YvR
         0FlDKtCAI/zUq+KA9cwt2OLLWO3Ge3NnElkRmMYxUdT/NSxrvDxheYD9wqERF3xVv/Yw
         V7stN2pixhwMe3k7JzDXC/BxPOe1QrexjBgJb9fc3sqEtYaZpMpIftv/7EyY7MDVawm5
         qtRRUqsLqEZY/RvPAsJR7ZE826tw5Vrn6V7yVKUlMxHX3ikwameZ+93fcE5jpVBwlu77
         xWnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RRu8Lpt58SWOttFC3+Kc87iiguBxiJbGcCvLScKWJG8=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=QbPHzMFls2PLKvAxg7FcUMZFuMAnKVt3JFDmTjkSdBKqjmG/U6Av+UzTT+ehWzcWEp
         kWzezQbedqy9BkZvsehDywD2TL/2sKiadHKpwQ4E+sHaKa3oR3wbdggJYbLR7f1rAYft
         A/SUuOi0ZJPE7AWGKF6GmgaAmQHPaOkNNa6wpMvPBFaJdO6S4q3oStiOQL1bTALyfWgz
         BgcpmFZpy24MYKPVKQLMX9xdJHe18CoqWJD7s4gJTGPngWdV8LoTgz8zOtC9v5maXBCT
         oX1WfkKk8Y2aoyr8KLxPjOkXMkWpS46lJO6CytPntO6mV77Wk7UXXOpQjvW5hkLQWQsG
         1/mA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JZSrHfV5;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-544b333f42csi239834e0c.2.2025.09.02.07.49.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:49:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 8B8DC437CE;
	Tue,  2 Sep 2025 14:49:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B593DC4CEED;
	Tue,  2 Sep 2025 14:49:39 +0000 (UTC)
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
Subject: [PATCH v5 09/16] dma-mapping: implement DMA_ATTR_MMIO for dma_(un)map_page_attrs()
Date: Tue,  2 Sep 2025 17:48:46 +0300
Message-ID: <098a7aace5780f8ad504ce021e7731dfe1f82dca.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JZSrHfV5;       spf=pass
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

Make dma_map_page_attrs() and dma_map_page_attrs() respect
DMA_ATTR_MMIO.

DMA_ATR_MMIO makes the functions behave the same as
dma_(un)map_resource():
 - No swiotlb is possible
 - Legacy dma_ops arches use ops->map_resource()
 - No kmsan
 - No arch_dma_map_phys_direct()

The prior patches have made the internal functions called here support
DMA_ATTR_MMIO.

This is also preparation for turning dma_map_resource() into an inline
calling dma_map_phys(DMA_ATTR_MMIO) to consolidate the flows.

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/098a7aace5780f8ad504ce021e7731dfe1f82dca.1756822782.git.leon%40kernel.org.
