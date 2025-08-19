Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB5HMSLCQMGQERNM2VKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id CE0B7B2CAD3
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:37:57 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-32326de9344sf11254344a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:37:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625076; cv=pass;
        d=google.com; s=arc-20240605;
        b=isRB34quwPrBCzdD/1QAGocB9z0bE5h9kvKbeLHYDTVGXmBKtU0M3CgHQZDBafIdRM
         eR8umMaGBDbmhtGqW12OCGnq12rF/nKN1HpSUeSEQ9hWjMwNIUsSVN0O8tSf17PFFa/j
         mnUjb9ybOyh0jguk+QSADiFIIkX8kZ0avLtZPfJN/ykWwPeamlUW6HA/f3T4Z81Qi/1v
         Bso+B9xwEXA20MS2DO8CbTZOYr2eOoy2pI2sYXkPEcDsODFmNM2taAtau8zLhnyrsxLK
         k+Y0je5P8nDtzzR2JHRg2gJt/4S3YXaGqSFwMM3XIbVGar0MIm3NA2CWZgo+b3DN0cHP
         vivg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=cm6yVVcx1BM5nW6MS86S+kBrALQH9o/g77xvUSsmxog=;
        fh=fKSJsjxxF3MhAAPTLphxNoeJtVf1eLBwhYilayuR/O4=;
        b=DLKNJLyoviFAAOg3WqS2hK/Rnux4JuC5AYdPJA+1ENsPw1URNZz5VdUwjdynS56Njy
         GM0nNRxh7BD0+GGYsYXPb52OSO/NZjaOhbXbrFccrB/ABkyvodBQ03ceCWH+2SsepmJ8
         9kAW/wB2vMlgWVsYZ7DKAYpPpoARWM/k7LikBNvNAQHGN8cZakOmzkY541fOeLXsDohG
         1Iv4zwQrqpvTyjXoIhTLVoLStMflfmAR2RHRjmMyCSzvoxP5Hrfas7Gc0TOtCyAzQW0f
         YUb2vCMTc6griSfLyk2XkbI1KKRHqm5SexIIqHQmlmJ+LBIvohiwr1DTMEomPC/PJaZC
         /pPg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KCfTK4M1;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625076; x=1756229876; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=cm6yVVcx1BM5nW6MS86S+kBrALQH9o/g77xvUSsmxog=;
        b=fAMav1s6e43LN/Ha40g+dUHrBMkyrx0Ql8wzQzt5N/RyjM5T2cCIXIEJ2sjaIX2cVU
         yZD3TV2q7AY3iwoahMl42xqIEAxq66/yI6MWwulumfpEnPHxhIr73AHxpRbfCY3flMnY
         Delq8hj84v0seYv9W6QsyDW2rSj6fT8rZiABOqWfVi8QgLQYKOIioZ2d38n3VeDX/f7A
         ME0++gx7yd35MtpsxRDaQmpWmEgHs0vGFB91b+em6ftDqVokSXVyGdpcY+RLGhYlAQCR
         7FGc/KegPnbFFbCXuurI9Ticj8HwQck2oWlE1xCxgWyS9AcwdHIZaV6viYk15C1q6jG5
         nJ8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625076; x=1756229876;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cm6yVVcx1BM5nW6MS86S+kBrALQH9o/g77xvUSsmxog=;
        b=Ic/Uc7J42eJclSnHYIzInIJqZ8PEOaVM1iU6zrrKNxKbf9ODBStDPDsrFDrBvCGagK
         6s3bNPcXIiplta7vjCvS694W2EYthlv0SoZSw8gBuh9H9BObBEuRz/y1Ytr5e90kd061
         I0DJ3iqExe95Hz6LjMxoWUO1siHRF9kuZr2u+ItimfxArRidQZq5wvWkMcPXYx+rqamt
         vwlxK09PDEwxyzwxd5fEIXdOAgpr4jR6QdHx0niwL5rh0s5YfXJ3R+I3LljPTVZ+8Lhn
         iPgq6hpyg5Fkvl2SViEj2nwtWPWNQFybuZVgpDx6VX+wpz5eWB5UJEpOwiIelHs4ai5d
         3QGQ==
X-Forwarded-Encrypted: i=2; AJvYcCXYPUhu64qwvcpJf0cXUdZhZna277CyVExst8BDF3YFWkp2d9LqNuzs5kZLSHOKnRYLHp4thQ==@lfdr.de
X-Gm-Message-State: AOJu0YxJPtvjFJYWA59Mzepz3ZtoGYL4vn/S3DW/2m5BLangHbz9g9fb
	oBUF+jcQprxWHZxWTKjb6b3xMcIaZSS8SB9cIiyfnlR4mU9FUGtzqr3J
X-Google-Smtp-Source: AGHT+IE+AlDUXVLlAo0p9HzCdp3XFyCfhw561RPTLVjUL1BS9lBebXsljLGMNLCX7EMxAge4bp7O9A==
X-Received: by 2002:a17:90b:1e04:b0:321:c85d:dd93 with SMTP id 98e67ed59e1d1-324e131b934mr115870a91.4.1755625076289;
        Tue, 19 Aug 2025 10:37:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdmfDgYVt0HrPoiBtxKueg94+ZaQ++k9MTjKn1ONPS+cg==
Received: by 2002:a17:90b:1d47:b0:312:f2f1:3aaf with SMTP id
 98e67ed59e1d1-323265a9906ls4887627a91.0.-pod-prod-06-us; Tue, 19 Aug 2025
 10:37:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV7QThDT/zgIe0YOw8mX6//JHNFrOy3mZPBHl5BHm7R5wp9INANEKYuD8+tarR1C6GdbV+rRsL0Gso=@googlegroups.com
X-Received: by 2002:a05:6a20:6a07:b0:243:a0a:efe6 with SMTP id adf61e73a8af0-2431b96f9a0mr271112637.45.1755625074530;
        Tue, 19 Aug 2025 10:37:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625074; cv=none;
        d=google.com; s=arc-20240605;
        b=hgin68WQpZmFPjaZl8y0jn+ZHqdJfFBjJq+xU75Kv5iNLcaxyEGF7nvXCq5T8D2xzj
         f/YeFuVC3lht2Hln/GCp5ytZ9ZzqiPQE26AEehspPmDchxDlAgwoIXxYO46DbqoQegZR
         FZ5QzGF6ugS1HviygL+v5t3Gm/t8FUye0193soHli8mpqSNitAxck7NfX1LK013eg3ou
         MHxkWuAIySorr/zmzma07TTbrVZMq+T7Ec9Od4wsZhOkyKzdi2XTRJtgqM8+fNiJ/0bK
         0AnaYqtVFRwPPWa1n1nSNxTvUXLrMceYq3ZDRL2D9qFInn7jFgfOGskw4adyn+5yvR5w
         mqAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+qkotKjA29uhp00A8rkqHQXkiTzDF9Aqh1SY8eRdGdo=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=juX/VsDZmAjhAXxfwTIwlkqjuwG+2VDq3/B4yj/9F3Wi4jL1vU6JoS66LBmRj0QWRM
         XFnVM8bWAsLctsiNEuxe3roHkMV+y0sgBJNRUCohrtx9PXbjDDRjkpjQyzVFj0ZENcQa
         nuqGUDyBMzAdc2Gg0DiZ/20MTTrxboArMffctqsS3irQJK8SerrHQOnjYOM5jXa/oyYZ
         4BIWAD3pfW4SpegWW8qrP42t85yMoMJkIOOFiaAKs458WCL0dJoz3KZBYxCd6GtRI+7R
         YWmiA0HxbfLQYl1uorJ3j/TFDrG8Jlo4+bO0YiymumASPdr9lJWgLn6gwMsU5SLV96SH
         U2YQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KCfTK4M1;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4763d61f36si20557a12.0.2025.08.19.10.37.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:37:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 8D1F260209;
	Tue, 19 Aug 2025 17:37:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 16E9AC4CEF4;
	Tue, 19 Aug 2025 17:37:52 +0000 (UTC)
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
Subject: [PATCH v4 06/16] iommu/dma: extend iommu_dma_*map_phys API to handle MMIO memory
Date: Tue, 19 Aug 2025 20:36:50 +0300
Message-ID: <4f84639baf6d5d0e107fd2001dff91b6538ff9ae.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KCfTK4M1;       spf=pass
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

Combine iommu_dma_*map_phys with iommu_dma_*map_resource interfaces in
order to allow single phys_addr_t flow.

In the following patches, the iommu_dma_map_resource() will be removed
in favour of iommu_dma_map_phys(..., attrs | DMA_ATTR_MMIO) flow.

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4f84639baf6d5d0e107fd2001dff91b6538ff9ae.1755624249.git.leon%40kernel.org.
