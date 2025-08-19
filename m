Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBBHNSLCQMGQEDQ7APMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 969F3B2CADA
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:38:13 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-7e870627e34sf2504339685a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:38:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625092; cv=pass;
        d=google.com; s=arc-20240605;
        b=do0fgPrN3PrbhAtAWIE6koZNnGri7JvHMm8DYMT3BfCZQnhVG/gfZaI1+VAvauPezU
         bps3OV2aW5Zvbnjr6VJZxa+CNYU9W0iIeBRBFm5+kewBzBMCXTjnCEpNo3ZUumM8IInj
         2jGACITITaRg0dZnP0f6mQcO/fpq6mWTsCdBwdhn9rJmk2DQpjNW1Utnp7g6JkYemt3R
         pGtDD43vEp5Q27CUzRQeJq3UKF0aE7SFKh7k/LK99IPVMK6bAiouTJAD9QT9CmLOvt1e
         o06hFmQt9Ryjvr3ZebAlqkS9adeDtq3+Je4zhs5PKZFdsfxTHO7cnUztw9lZfL606v53
         l4qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=uP+nOS68tTJWnxZY6XHPUuyOgDeSpfVRaaI10XV5xk4=;
        fh=NFlmWvhi8FD1ghyJOJW6RGbPeNaykpst7tcp1oiEFqY=;
        b=jImTkTOcmyeFgeXVPkDTF2OboJpafvQ5MetqMegsORemAhHVilDLu7WmKxgupYdlXc
         aq8qsgWi4HyENLUbvqofSQkE/2wNqJZifZlB7r1AXW1qnR77hMEMq1wZDORqQudmAMKI
         bRGPTGsODwQQDmwUhkveDTapecHhVLfZldHxI/xc466jPR+jLIvc2DJVMJARlcSe5T0V
         f+2mdslMtNGgnIiduVLPF1+xf6HcKRgk3P0Kstw0rj0bvnzLA42ZMG1VWnlLtYYi8z5o
         ON3y3lPO4AFStchc5FmptbROMUVmjiTB9psorc8LepiCp/Lvxhi+pLsPTKrsi47kQtLd
         lU5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MouP3Mq9;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625092; x=1756229892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=uP+nOS68tTJWnxZY6XHPUuyOgDeSpfVRaaI10XV5xk4=;
        b=VylXsoB1hljwXq3NufmQgAbzbob9rhmeyTucbb45/BZ8mm5sI0t7HOTKHBJT3tTHKT
         wWyI410BeyR4qWMxHx9gQ4QHfUMxUawt27qogpMhJ/I/wVcC1zg1TSbCAwVrT8LNRPPl
         iVkWKyrbERTmTzGYa+09XLMnufhYs8nCBQQsspgpXzcRNj+kUKq81PaPKIGiDqgtdIVE
         4WISXTG7pjO493fBmbcUQCyAnFJh7NM4yJZxWghHF9SMAjPgpmrh+GRG3GsOHe406kNe
         3UrSPtbejYyNtf6RQmq1UA0Czy+3NaVw+VYn+WowG9f/dpBdJlFYbusnCLwweXjOplx5
         U6tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625092; x=1756229892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uP+nOS68tTJWnxZY6XHPUuyOgDeSpfVRaaI10XV5xk4=;
        b=qGQird9SXrEwB+KeW5g3SBfdQLPv6rlPtFXUz4wvGgkqw6vRG2NBS7BEv1oa/StTA8
         lKK8JxkqW1zcCbDD1qWvLIryzfXP/48Vp++wsXE0pSwcA5maXQcz1ZGPEQwDon7RDN9Y
         aJ8wFMbqBUOOTSa63f7TRDo8R83xW7lgYl8flLnNw8/kw5AdK19diwTOLc7aGyiLzBZP
         7Vc6mhLTaTpRR0IKOqXEho9zch7FS288cQ+xzreMPPslF7koqNd3OUPz3BnGY5wg+KwO
         JbFwIplipg+Dv2e8rts4vMX+QOLhFmU1nWeDD8vgU/piyrLAlAD3pfqCewJyIrpPvgtT
         45tQ==
X-Forwarded-Encrypted: i=2; AJvYcCWbCxTY+Ft9aMsct2NfhB6hJB7pab2HFyl8MspipnugKcH/WNGMrgtr/EpkEAshOqPIcNfo0Q==@lfdr.de
X-Gm-Message-State: AOJu0YxpbQUgl6IYeRyVcRxzF9zODsL1R4Wi55Fq6hZjaUxBGUZ509rQ
	wURQnYTE524E40K5SafJMtI598qMtldRuAf7ZQaar2U56XKc2baHiT6v
X-Google-Smtp-Source: AGHT+IFp//a6m9G8khhxmW0cpAUuV0IUYr2KHnQeUZ65WJa+AvhzgHBpjAfYgDiUwlCi88edMv1PkQ==
X-Received: by 2002:a05:620a:7105:b0:7e9:f820:2b59 with SMTP id af79cd13be357-7e9fcc1b27amr7416085a.81.1755625092320;
        Tue, 19 Aug 2025 10:38:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcbb93rdnNNNr77v1UvZcJ/E21e882DYAaL8jylV1j7yA==
Received: by 2002:a05:6214:4588:b0:70b:b18a:cc7f with SMTP id
 6a1803df08f44-70bb18ad469ls32175716d6.0.-pod-prod-06-us; Tue, 19 Aug 2025
 10:38:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuE+vq1clTXDFfJjzXR1jFRAIh2RM2z+dpa3GFQZ2xzQX8y9zJpND1MAAAG4bS+i8673yqXTezihg=@googlegroups.com
X-Received: by 2002:a05:6122:3bc9:b0:531:19f4:ec19 with SMTP id 71dfb90a1353d-53c6d6175acmr69189e0c.9.1755625091129;
        Tue, 19 Aug 2025 10:38:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625091; cv=none;
        d=google.com; s=arc-20240605;
        b=hRNtkZiPlQx/k5uFHqUYHwihqWX88mwosQmFBMrCt09Y8NN8szoLyTYid2QraDuiah
         VMaz6X1S1uZfodDOazEVR3P8QRggJ0MJmDFbDb2d/RVbBIGyW/HOvdB685Ko8EtOIjha
         67xZpGh4wQJKCF80cdVnmr3hJgBOOa+HercXzbl0uQHOEBx/IWagn1MMgYmVI1NqTMxi
         71SpaH77l9wsk9HPpwj9cReuGLcutgsrPybcXDUSmdQGLYs5RH5Od/kRHV5bcZ4EO0kn
         DyKkmpRJEB/YI2fO5VY46emRK5f4IIYGzc/7esTtzMSsIRt3KAfW9Bf9ZXxNEGnPwWQO
         KaIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kCJU29SWd1OR3k6ZUoBci43zBS+gLO8fdMAUUcFIoOc=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=Cm72o64X5RGl3yZMrWNe00QohnBuOtev/3LifaOqR6Ccwh+Gd6khquq6VU3iTOb/pY
         U9jfXQqVDBeWWTOYaA9GQpb70j7Yh2x9jmBKFu/mmk94HvYII208n/sfNpsRGFO1JnUu
         DmcB7Ue1ng2q4Onk4SUKB1hwS4kNApj4w4pJrJttXqMfRiyXe9rPi7msC4Mzic0cPvDf
         Bfw8D8En8RuVjw1rIyLNJg5E3u4eDkvklft/I+MnqvVci5E+nLteJcYsEZMrrDzc//4e
         FLf3TQGdXQj0zS76O+xfyhNFp6RgcW3k7J2rWfP9RdHPbm+wPi1eXghcNG7OYTKVetzi
         xQwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MouP3Mq9;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53b2bf8dcc3si472574e0c.5.2025.08.19.10.38.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:38:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 890FC5C64A4;
	Tue, 19 Aug 2025 17:38:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E64ECC116D0;
	Tue, 19 Aug 2025 17:37:57 +0000 (UTC)
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
Subject: [PATCH v4 05/16] iommu/dma: rename iommu_dma_*map_page to iommu_dma_*map_phys
Date: Tue, 19 Aug 2025 20:36:49 +0300
Message-ID: <66e7cc6854e4e40278b598b38e0c4d49d7fcec91.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MouP3Mq9;       spf=pass
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

Rename the IOMMU DMA mapping functions to better reflect their actual
calling convention. The functions iommu_dma_map_page() and
iommu_dma_unmap_page() are renamed to iommu_dma_map_phys() and
iommu_dma_unmap_phys() respectively, as they already operate on physical
addresses rather than page structures.

The calling convention changes from accepting (struct page *page,
unsigned long offset) to (phys_addr_t phys), which eliminates the need
for page-to-physical address conversion within the functions. This
renaming prepares for the broader DMA API conversion from page-based
to physical address-based mapping throughout the kernel.

All callers are updated to pass physical addresses directly, including
dma_map_page_attrs(), scatterlist mapping functions, and DMA page
allocation helpers. The change simplifies the code by removing the
page_to_phys() + offset calculation that was previously done inside
the IOMMU functions.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c | 14 ++++++--------
 include/linux/iommu-dma.h |  7 +++----
 kernel/dma/mapping.c      |  4 ++--
 kernel/dma/ops_helpers.c  |  6 +++---
 4 files changed, 14 insertions(+), 17 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index e1185ba73e23..aea119f32f96 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1195,11 +1195,9 @@ static inline size_t iova_unaligned(struct iova_domain *iovad, phys_addr_t phys,
 	return iova_offset(iovad, phys | size);
 }
 
-dma_addr_t iommu_dma_map_page(struct device *dev, struct page *page,
-	      unsigned long offset, size_t size, enum dma_data_direction dir,
-	      unsigned long attrs)
+dma_addr_t iommu_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		enum dma_data_direction dir, unsigned long attrs)
 {
-	phys_addr_t phys = page_to_phys(page) + offset;
 	bool coherent = dev_is_dma_coherent(dev);
 	int prot = dma_info_to_prot(dir, coherent, attrs);
 	struct iommu_domain *domain = iommu_get_dma_domain(dev);
@@ -1227,7 +1225,7 @@ dma_addr_t iommu_dma_map_page(struct device *dev, struct page *page,
 	return iova;
 }
 
-void iommu_dma_unmap_page(struct device *dev, dma_addr_t dma_handle,
+void iommu_dma_unmap_phys(struct device *dev, dma_addr_t dma_handle,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
 	struct iommu_domain *domain = iommu_get_dma_domain(dev);
@@ -1346,7 +1344,7 @@ static void iommu_dma_unmap_sg_swiotlb(struct device *dev, struct scatterlist *s
 	int i;
 
 	for_each_sg(sg, s, nents, i)
-		iommu_dma_unmap_page(dev, sg_dma_address(s),
+		iommu_dma_unmap_phys(dev, sg_dma_address(s),
 				sg_dma_len(s), dir, attrs);
 }
 
@@ -1359,8 +1357,8 @@ static int iommu_dma_map_sg_swiotlb(struct device *dev, struct scatterlist *sg,
 	sg_dma_mark_swiotlb(sg);
 
 	for_each_sg(sg, s, nents, i) {
-		sg_dma_address(s) = iommu_dma_map_page(dev, sg_page(s),
-				s->offset, s->length, dir, attrs);
+		sg_dma_address(s) = iommu_dma_map_phys(dev, sg_phys(s),
+				s->length, dir, attrs);
 		if (sg_dma_address(s) == DMA_MAPPING_ERROR)
 			goto out_unmap;
 		sg_dma_len(s) = s->length;
diff --git a/include/linux/iommu-dma.h b/include/linux/iommu-dma.h
index 508beaa44c39..485bdffed988 100644
--- a/include/linux/iommu-dma.h
+++ b/include/linux/iommu-dma.h
@@ -21,10 +21,9 @@ static inline bool use_dma_iommu(struct device *dev)
 }
 #endif /* CONFIG_IOMMU_DMA */
 
-dma_addr_t iommu_dma_map_page(struct device *dev, struct page *page,
-		unsigned long offset, size_t size, enum dma_data_direction dir,
-		unsigned long attrs);
-void iommu_dma_unmap_page(struct device *dev, dma_addr_t dma_handle,
+dma_addr_t iommu_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		enum dma_data_direction dir, unsigned long attrs);
+void iommu_dma_unmap_phys(struct device *dev, dma_addr_t dma_handle,
 		size_t size, enum dma_data_direction dir, unsigned long attrs);
 int iommu_dma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
 		enum dma_data_direction dir, unsigned long attrs);
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index fe1f0da6dc50..58482536db9b 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -169,7 +169,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 	    arch_dma_map_page_direct(dev, phys + size))
 		addr = dma_direct_map_page(dev, page, offset, size, dir, attrs);
 	else if (use_dma_iommu(dev))
-		addr = iommu_dma_map_page(dev, page, offset, size, dir, attrs);
+		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
 	else
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
 	kmsan_handle_dma(page, offset, size, dir);
@@ -190,7 +190,7 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 	    arch_dma_unmap_page_direct(dev, addr + size))
 		dma_direct_unmap_page(dev, addr, size, dir, attrs);
 	else if (use_dma_iommu(dev))
-		iommu_dma_unmap_page(dev, addr, size, dir, attrs);
+		iommu_dma_unmap_phys(dev, addr, size, dir, attrs);
 	else
 		ops->unmap_page(dev, addr, size, dir, attrs);
 	trace_dma_unmap_phys(dev, addr, size, dir, attrs);
diff --git a/kernel/dma/ops_helpers.c b/kernel/dma/ops_helpers.c
index 9afd569eadb9..6f9d604d9d40 100644
--- a/kernel/dma/ops_helpers.c
+++ b/kernel/dma/ops_helpers.c
@@ -72,8 +72,8 @@ struct page *dma_common_alloc_pages(struct device *dev, size_t size,
 		return NULL;
 
 	if (use_dma_iommu(dev))
-		*dma_handle = iommu_dma_map_page(dev, page, 0, size, dir,
-						 DMA_ATTR_SKIP_CPU_SYNC);
+		*dma_handle = iommu_dma_map_phys(dev, page_to_phys(page), size,
+						 dir, DMA_ATTR_SKIP_CPU_SYNC);
 	else
 		*dma_handle = ops->map_page(dev, page, 0, size, dir,
 					    DMA_ATTR_SKIP_CPU_SYNC);
@@ -92,7 +92,7 @@ void dma_common_free_pages(struct device *dev, size_t size, struct page *page,
 	const struct dma_map_ops *ops = get_dma_ops(dev);
 
 	if (use_dma_iommu(dev))
-		iommu_dma_unmap_page(dev, dma_handle, size, dir,
+		iommu_dma_unmap_phys(dev, dma_handle, size, dir,
 				     DMA_ATTR_SKIP_CPU_SYNC);
 	else if (ops->unmap_page)
 		ops->unmap_page(dev, dma_handle, size, dir,
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/66e7cc6854e4e40278b598b38e0c4d49d7fcec91.1755624249.git.leon%40kernel.org.
