Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB5PN63CAMGQEB4MGGCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AA99B261F9
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:14:15 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-76e2e60c3e7sf1398723b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:14:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166454; cv=pass;
        d=google.com; s=arc-20240605;
        b=CpM63ICXKQOYdJQ8oZuUaYjsitsPO2VVFpLWNAHzbXEnvDLtABKf1ApXVaVYGqHyBC
         dZiEAOlfCOHK9E3He3MocsSCI7VsV9fk7vKQsWGMrsaVlyrKR/VL2ccrqqF6UKIHFQet
         +mPhF+Sa7LH3CB5OEDXUBY+d03ytJick2rJU/7JvyschMwQNa02UqAmzVlv5zpZxb7mF
         6jQhQpCWcHu+DKkrg9E3ry+OB+iusO/ed5HF2xDKAy8ZVVgKQ2G/PrDNS8eRBWsSCPy2
         YrEz8VB+FdKM1pXMffW5MathIESRj3ov3D7i4AteW7EyeXlYMZh5uq+WfT7ZHiZi0Qji
         IjcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=vdeEbXw+/EF4ALPp12Wb9SwLr6psVErxMwV6KWReHLM=;
        fh=98ms+z2pnrplpSx0WB08AwJhiWyjZDOesoPwtJChCHk=;
        b=clHOkvb6l90b1z+I/eeTdJARl97IOB7gY7MWes9q4WuZ3OLtEkv+Ox2vl7SHyb89CL
         L7BdW5nNZ8mPx1gorVgnPWvohCtZTBhujk4PZhKC8K3LMXVq4C4wpkQ0firIjVI1oAqu
         AWpsk5ocLVynaEs9PvhmxCwffWlwFD7XudHALN8LZ7l3MpHM1VSi7o6eU/waVVhacI8h
         5qDWbXm540dlALm4QFrGU4kewY9Fd3tMdkreiaQBaznsaz4NwZMs8OVMpSda8IIluOVp
         NAw6NOjmnjiE3WhC3Kpr+FMxP0qf7j/OPsji6NsK6AO8VSJnHzFs1wqLWzmpp0p1L0W4
         7i9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gYSTOUUB;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166454; x=1755771254; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vdeEbXw+/EF4ALPp12Wb9SwLr6psVErxMwV6KWReHLM=;
        b=GQYssRr3T5lKktY8/tSmdP/AtSRubk6I+wZ9xfzY7tru/PBQUD6wfeL9uGKLDFznkf
         DngJO2fMBXtHLoRcTNVhi+AI/ZqWbkG7K3y7FlVX1ZJ5DT3rE9mCLU/cMK0Tbl/aUsz0
         ZS5NSRS84BszgGBAsRN4wDb1Xe2VcOuqJxfLj9LYo+SH6BNQw1+S0DgawVuqu++OozW8
         HHo8Jn+wmdGkDpsC8zxwETwHnNYCfIpxGo/1+V4c/M2KMesgaethxzCVxPNhIf8v7XTW
         UUmm20/F1Qktm50RzmM0z5cvXkieWCZokCDwpUQV1GnCOnNY0dBKwOBvqAFNaCez6+au
         IFAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166454; x=1755771254;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vdeEbXw+/EF4ALPp12Wb9SwLr6psVErxMwV6KWReHLM=;
        b=Jvbn0myFQzbAHbYk6puiKqTCdWDAUFDgVhjvJNgPvbvztVmjMRYg5KCLpGGZpxbqHk
         2hBCU7Fe+GXACwaoxVXfewE29pvysApaQ9+fKfeEfQkmyDhjv7yQ2UK9KSJrOZ66CEUF
         zg3e6kPSF88rCc+3LwY6FGFbZnzrygu78pVlFX5MF5+AwOMRYI4hngs/0vuwLlTY58RM
         gCF9mdYY5La+gWb040nHmFqMYFVX3weurbupBDb6L+fcf4x3hhkLQ1P3MSgrSSosCM3s
         SVr0nei9sCf0XRqekLtdCh5ri9S+MNRHBshtXDDglLfyENzdyDzPWGM+L2ecE3I/5gFa
         gCaQ==
X-Forwarded-Encrypted: i=2; AJvYcCVZiR61L89bf4rN0/a595pbfDk8uqkg/V+aaTW+P6qWzp9ueHpmQQcusLuKuZdmJMWLqYuuvQ==@lfdr.de
X-Gm-Message-State: AOJu0YyMKl3ViHSVmzMx+es865Sxd2pYjNLkysM73Z9yiXbVHdJLgkoP
	LZoSjZeUT7mfu3MXawkxGxpua4b0gzAhRpI3iioJr4wtqFLI+kbo1iBd
X-Google-Smtp-Source: AGHT+IH7E+epYcNU8wgaaft84trFqh9A9MO5nuIaQ80q0x8KnQ3kzkuT7pLYv+SiExxz5AMr0fKXzQ==
X-Received: by 2002:a05:6a00:130f:b0:740:9d7c:8f5c with SMTP id d2e1a72fcca58-76e2fbaf631mr3910301b3a.18.1755166453818;
        Thu, 14 Aug 2025 03:14:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe0zhKyEYN9qnDgycqbwqQcHnn+jzUtU1nWN8Q8L3qLfQ==
Received: by 2002:a05:6a00:1c89:b0:742:8b2f:6e98 with SMTP id
 d2e1a72fcca58-76e2e1d2990ls773697b3a.0.-pod-prod-08-us; Thu, 14 Aug 2025
 03:14:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXyHy5wYEpi5L+4QtJOy6+o0gcCXAhEqjpl5tqpSYnSy8KEGYRd8Gs19LN8C2QsEtprJAKlPWRgUH8=@googlegroups.com
X-Received: by 2002:a05:6a20:394a:b0:240:1241:5f2c with SMTP id adf61e73a8af0-240bcff9e71mr3752711637.10.1755166451526;
        Thu, 14 Aug 2025 03:14:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166451; cv=none;
        d=google.com; s=arc-20240605;
        b=b8IVNoOX0aNxWTD0kNaeH+VDYBXUh1rBfCNKS769UgalebqAeKpdTnBNdZiQ+uIq+w
         LqdGywXwADgtxt2Kpq7CZBHmCuPUEwMFY34hWIN9X2CdZVz1GkGnG0KRPUSfb03L+S4o
         fJ/LEW9Mb65yEiq+UQnLWzuos6w0PMrXIuXq6VTY8xG+h/VfTsmqd6bKsTHIM4ps/pOw
         5ZY8NVGHrFGwScb4I4HVrBvtmIluKUACSwMcSOWkTPL6OmRCa0y6ZzrJQsMnRyAgUB6w
         kygamplLzTl13MgtKdebIhznCahqqnAUkQu29TZI7VKYq35UQ535Q8sogmicN7sGvl1l
         MBhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+qkotKjA29uhp00A8rkqHQXkiTzDF9Aqh1SY8eRdGdo=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=ASMsmbHUiuA4oMy7Ei1ffSP+iqDvqXmpn0AAmJQkOFNuLUJPNx0R5EszA6sISb7zFU
         4rZeBa0RieamW0vIAdcmAXgeZc7hYbnbRMhBJSVa7q+SDR8cPn1tCuy0bKDmI4i2yB3V
         gal/Mq1/wYHcK6+qDNG7PutB6iinC95Y3Dvh7ntsu8qxma/vib1OV6EXzL9T1AihhhjA
         DV/3L5hVKNdt+VQeCxmTkxTGIHyIketguedS7Hz8UFCnD4pvhmBUeATs26PAfLd86P9Q
         50nd1xx8RZeEcoyLUdfjcBHDmRv4/t5vGeOrzNdv9wy9PGODRTYX2NB6WFDy8fUIEHwH
         RdYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gYSTOUUB;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32330da89a7si51817a91.0.2025.08.14.03.14.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:14:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6330E43582;
	Thu, 14 Aug 2025 10:14:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 85A63C4CEED;
	Thu, 14 Aug 2025 10:14:10 +0000 (UTC)
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
Subject: [PATCH v2 06/16] iommu/dma: extend iommu_dma_*map_phys API to handle MMIO memory
Date: Thu, 14 Aug 2025 13:13:24 +0300
Message-ID: <3086f426f3ded9c671e9a6441810c21efc9ad87f.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gYSTOUUB;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3086f426f3ded9c671e9a6441810c21efc9ad87f.1755153054.git.leon%40kernel.org.
