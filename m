Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBCMI3TCQMGQE3SLAHOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id A09CBB407A7
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:49:47 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3f2a2b1357csf113346235ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:49:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824586; cv=pass;
        d=google.com; s=arc-20240605;
        b=gCrTXVCUbu0VcpR9B6kIxwG7K6c+tyqo1nKxuqrMFQ+4oiKh7nv8IcTDmkaWOkRMuK
         r5BJQoUaEtae8iRVXVFUNKpP7MmFAYwe76DAGn9fACtTX6cmThaNcg2QT9evitKrjSF5
         HfgbcYWcECrGWekBBAgGj5IXfj6a9e93oW7Cci+Q/yX1tsym6rV91S9HX01Yz7jgZDim
         PYaral0qi16gRDPjYA5xT75mFNFE2uOZjM4CAtSCEFbBCri7L/iqQyLA6Sa0RVBOEn1b
         2PERP1Rt9LAM7emTnALPvaNSlIrs2iiJNGmUtq+IYctAp0gdAhNaX1jJrHggVfPMBeaR
         3iNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qM7TwXJykHZBKqE9jRRyQPWi/EddNZFYYgNBnJH9sBs=;
        fh=RkGVZTeXNaMJ89i2fVCsQAP/xQb+EGxBJlqJoS5SjAw=;
        b=MwBaXZuuVAHlIhfZ+7wjDhM/DM4F6kTmByfWu6rc11GWTEkEsCAsaP2+VL+hy7LJAX
         rFXWlZwiCusPiG7pTyM1nsifktfgGWm+x1x1PWxQGHKhRWbGN5SOKsCCdJ8PcAi0ZUJ7
         +eBEPu2srqRFcjLyV04AhH4i7L/YQOwPC2gK0a/363g1uwLA3EQAHKkllpjgi8j686OM
         U57jWVq+RLR7j9qpjd/dy+XLG+TcKM8qVy2H9nVwTQOshWw0Wm4IhI1jOJjXkQ1WB5Bf
         1vtAaQUuQ4adYGms05p0SultKewXshTSCztW6V3jDvUy+agSBLBHS+CVl6ZdJbS6uwcf
         M/sw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VKECAb+7;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824586; x=1757429386; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qM7TwXJykHZBKqE9jRRyQPWi/EddNZFYYgNBnJH9sBs=;
        b=Yx1t8T7XSfFjxsqx/wkNJOqrEVZDqhOU35fYvU2eOZW5dbtBHPO53Bp8+xgb0Yu0Rf
         Z4QRbwOBl+SXhCWUmpVv3sewM6zR9ncEDB1ItTUt8wsfQDBOAd6WcMHzOCJIfaFQLrSK
         77IIlRJp3R+Mgoxu7kxm0wXJSFCXuaTQYh2d1s7W+yMmqvhhgzFfaAqcw3XB46sL44Mp
         Ywa35NX1wrUysG8F/xTaTD5ACvu3zuKQGvSKLpIK/5ocw+29Tr3ipW4S4myxYMmTnk9j
         5NxxPGt4PmFgAnQYYCOHhOqWPKJeOA0vJsQRasjT1+QSTyb3WUeP1EvoiTG6Ri4gOqW7
         Q41w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824586; x=1757429386;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qM7TwXJykHZBKqE9jRRyQPWi/EddNZFYYgNBnJH9sBs=;
        b=D3Jw5FlLqJuHO631drdzwGR+5U2+1M7DdouKPi21aVig8PZAAfbhmbUcdrsec3vgmX
         KijWfAjWW4C4sMKFWKyPdIEvRwpvbOJ5XjZn7M5KbiMuugld/Ciaq6RMq1A5p8LElWuC
         Gr0ZqwZpf9s4KP6GO6JT3Q4iwCVGs+nKrG4cYE7FealuJCiyGOaStFuTuj5BcVB61VZt
         HLEbJ87tZopARKCRuVtVvZ/1R9/vzZi4WlfpQz3kxCzm8Ca3CLGbthg1I+OaQN0qKNia
         LeNYmTE5XjzhMPn2S0w3g2Dfu9oI/YYjn9S34nKw5PYS1yNxgaUZ9vGDH4cAJX3y7V4F
         tKmQ==
X-Forwarded-Encrypted: i=2; AJvYcCVwhtEtbbjZW6UEFuEaWmqMlHSjOIYtCn+8h13ainJlfIWqDPoIwrQ3EYuJLyqf/wi2ZMNmPg==@lfdr.de
X-Gm-Message-State: AOJu0YzMYiWUTt6Ow6GmGD3TpK3ruOEY14voFOmj68rIeukJhatqtvUC
	+V37imJU256jgL/VUUtIArhzovyUQ4Ep3+uY2uYZSJkXvN4dMe/nMZda
X-Google-Smtp-Source: AGHT+IG4PPqecUxBcmSCxMfGlbwBbIAso07CQwe2DWwv80F+ZcLXDBN8rJDBIFLgp/kMzvgFPt7ibg==
X-Received: by 2002:a05:6e02:4609:b0:3f6:5bfe:89a with SMTP id e9e14a558f8ab-3f65bfe0cb5mr16885915ab.13.1756824586139;
        Tue, 02 Sep 2025 07:49:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZejZ0O4PtP0eUxX2bUVAwAgvYUYiqdh3Yvs5lOQlzgAEg==
Received: by 2002:a05:6e02:3044:b0:3ef:78db:8b36 with SMTP id
 e9e14a558f8ab-3f358fd23f5ls36818445ab.1.-pod-prod-02-us; Tue, 02 Sep 2025
 07:49:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUwx1lfyb8GnKHi1pVeQvrBh/5x1CAdKx2XLYnaKPlrST8vMy/spqu/JGuvHGU7xdS7QD/hLy7yVkQ=@googlegroups.com
X-Received: by 2002:a05:6e02:1c03:b0:3f3:d923:d667 with SMTP id e9e14a558f8ab-3f4026bd7edmr33436465ab.29.1756824585227;
        Tue, 02 Sep 2025 07:49:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824585; cv=none;
        d=google.com; s=arc-20240605;
        b=NGbkajbxC2lWpGxTaz17ZR+SwV2c/cQoYmKUV8xLobmiUR1tazzgPdF13Ch+LIbsfT
         hzMRc/vuuad2e61PhcOK93LrW8PDkVn1d32844g/axhP7dYeUZm4W32nt5/8vtsnCTXY
         TcKJVuXocLdqmQyAFB3pISn0GqIMnQHOazWM6Yo+Z2u8z+1OrvUbuDD/GxB9k9CO4uE5
         6L+6iYJvGqDo3E8aYYnmwLraT2KWS5i/8tEPq/alTJSxn9jatxj8c3lDpPvyy1rYRX5v
         TP37M1MvBVpriQU+UazsbTyYaxMHp3uS8LfOFm3eNzfu7e6BMOb6oXiXcTJIIxONfrHI
         CMBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6APT/ghoDYbBmlId4Kq2wmBlk0N08YJMkAHkbYOh2K0=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=Y+Tcpk1eiGtA8RETcv+sIy3VxUFYhzx/9B/3k99qZd3vTYsOegEFyFIZupNaRYirE8
         SId3633V2BGchfiDOEqqT2zb17TfHWVxf9or19Enb8d4FsZmkJhKhJ3CuaNUa59BXuiF
         9nkOZNrdkuYRSwqzsmL5gpijhsMXUwEmIHU6oVQVqpxZZ41lijwWunOlxD48UwJh+GGL
         pPjhe7n7xNQzK1QR9XndlMd9l26a/VMr6kFKo93eb7ffFQ2L3nwoBcZBvgY8/uLMqWAc
         vzjO39f6nPSOn8sju1/hp7oDHGDEs5sUXDF1R2SDO4JUVqsrLlFeiZhxMaap37NJ2YT4
         Vxbw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VKECAb+7;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3f3dfb57a21si4038625ab.3.2025.09.02.07.49.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:49:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id A23706021B;
	Tue,  2 Sep 2025 14:49:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A66F8C4CEED;
	Tue,  2 Sep 2025 14:49:43 +0000 (UTC)
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
Subject: [PATCH v5 06/16] iommu/dma: implement DMA_ATTR_MMIO for iommu_dma_(un)map_phys()
Date: Tue,  2 Sep 2025 17:48:43 +0300
Message-ID: <615b270dc8cd285c1b05cf3b9d3a969487049a5f.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VKECAb+7;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
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

Make iommu_dma_map_phys() and iommu_dma_unmap_phys() respect
DMA_ATTR_MMIO.

DMA_ATTR_MMIO makes the functions behave the same as
iommu_dma_(un)map_resource():
 - No swiotlb is possible
 - No cache flushing is done (ATTR_MMIO should not be cached memory)
 - prot for iommu_map() has IOMMU_MMIO not IOMMU_CACHE

This is preparation for replacing iommu_dma_map_resource() callers
with iommu_dma_map_phys(DMA_ATTR_MMIO) and removing
iommu_dma_(un)map_resource().

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c | 15 +++++++++++----
 1 file changed, 11 insertions(+), 4 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index aea119f32f96..6804aaf034a1 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1211,16 +1211,19 @@ dma_addr_t iommu_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
 	 */
 	if (dev_use_swiotlb(dev, size, dir) &&
 	    iova_unaligned(iovad, phys, size)) {
+		if (attrs & DMA_ATTR_MMIO)
+			return DMA_MAPPING_ERROR;
+
 		phys = iommu_dma_map_swiotlb(dev, phys, size, dir, attrs);
 		if (phys == (phys_addr_t)DMA_MAPPING_ERROR)
 			return DMA_MAPPING_ERROR;
 	}
 
-	if (!coherent && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
+	if (!coherent && !(attrs & (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_MMIO)))
 		arch_sync_dma_for_device(phys, size, dir);
 
 	iova = __iommu_dma_map(dev, phys, size, prot, dma_mask);
-	if (iova == DMA_MAPPING_ERROR)
+	if (iova == DMA_MAPPING_ERROR && !(attrs & DMA_ATTR_MMIO))
 		swiotlb_tbl_unmap_single(dev, phys, size, dir, attrs);
 	return iova;
 }
@@ -1228,10 +1231,14 @@ dma_addr_t iommu_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
 void iommu_dma_unmap_phys(struct device *dev, dma_addr_t dma_handle,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
-	struct iommu_domain *domain = iommu_get_dma_domain(dev);
 	phys_addr_t phys;
 
-	phys = iommu_iova_to_phys(domain, dma_handle);
+	if (attrs & DMA_ATTR_MMIO) {
+		__iommu_dma_unmap(dev, dma_handle, size);
+		return;
+	}
+
+	phys = iommu_iova_to_phys(iommu_get_dma_domain(dev), dma_handle);
 	if (WARN_ON(!phys))
 		return;
 
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/615b270dc8cd285c1b05cf3b9d3a969487049a5f.1756822782.git.leon%40kernel.org.
