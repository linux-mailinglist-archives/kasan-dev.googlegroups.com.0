Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB7OVYLCAMGQE3HT3XZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9559CB1A1AF
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:43:48 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3e3f9dcb1d8sf76040305ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:43:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311422; cv=pass;
        d=google.com; s=arc-20240605;
        b=gTqTAq1bxjVVlJepzumQ2eIDIUXQrPlJww69igoAlRPe3B7JcnWYMRluqoQEaQO0tN
         54muCTAWG5gPcDVWNbZ3CN6O449JRzZQU+E0TBPhBAaT+BbbgUFmeNJ7ABVY5WDszFwD
         p9bXSLVxPpdarAqCZ2dsYZJzgUObJv3JCIrunid3fKbdLsIOShDUk4aIUNxPjH+D0smt
         LzQmAOSwf5+9doVOJigJOWvW8w0KJ96ZmO0X7nFImB6kEQd7C/rqNhh8dEele4cdmXVl
         fQeIcmrNES5DQP3E6loSIQNWcVOJCQ6LftAuyQMPTF11d5GaPRKmBPc/RzcxWeNemnNk
         ZE6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=MvVAILpqko7fuMTQvqxbAT8bUTmeiBNuQqkTg8h0drI=;
        fh=9GGmwR7pqdCyWp4qW/C6vEoVeNJCjrYwjSdnwtiVXTY=;
        b=h4PipA3EkBNyo9ulkUE9pB+2XfdR4c2IvVW9EvxKbc7ibEkb2ldclnv1pChOAjZqaH
         1LTAACGTrXmPbI6QZ1peirnyT9ztVU7LnzXPK+FfyzW5c6MfryS3XxvooUKT4JFsGTRX
         RKLUDfoVz0iB7thvk0WHhPo/yebldfijp+h0g1M38b8qLs0H8KJf1iUMOjOBRYJpKiS/
         tX16OjZLBE8qgYE4bDR4UaE4zmtzUspO70Rura//QHnqXeqYcSQ9CVsakAhj3Epsg9uD
         Yy26pnL3GZFykT9cHeAwDiH8uGz1UQ2c9y2+x4KRCEg3vm+cJD9t2Wb8n9H41fEf+7/f
         Cp2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="hwpc/2Lt";
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311422; x=1754916222; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MvVAILpqko7fuMTQvqxbAT8bUTmeiBNuQqkTg8h0drI=;
        b=XmS/9/oREDmhICVN4AcsJUa8yCTwxSEuMDTOBeBq1+OAaOpcRJRZBFvArO9Ef1UkUF
         lvmCXv8if3GbYz5gsI2hA3SalOVm8E62Xn18YIll8q4F7X6q3HovA84OTopQEVTZUem8
         CXifdRSkMLKQkqlzhbqhWSf94jh2Lq9sS7zOWYsedkrYk5XvtKxA941TU4VszvHM/aoC
         QFMFzsVJALJJasvn9FCCw9D8gECre9E8YNdgFucC9uGhQqSjG+f3tQ/9jYcPVX4T1AH3
         SM7Cp69eja4aGH8dyfEmtONTdi0nBLRGS8a/I+zxY2Ozjpe9q1I772x5ta3ZWdi0nuGz
         2wFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311422; x=1754916222;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MvVAILpqko7fuMTQvqxbAT8bUTmeiBNuQqkTg8h0drI=;
        b=tIxAOlhWO58O5VbfPqYlmqGgLm7MpI+dCVU8egif5KcfYRdHy4X+UF/K0PlxdtOXkJ
         rHhgJ7yuRJLuBHGm2LNaKkVZ2TWCYfdYhx3xy3sLLXgVm/vfLUGhFb+a0pmillzubM9T
         Ud7upDHi6w+gUv/ugb6gcqW8ZMwjzTX+NOd3sqqT5z7VAMt29iHSyl56J49NVjlqfzQP
         T89Mh6qEqouc4Pe8xUwsjK9Zgp1OjkYhrr3VJ49gm9Q4vCVJ2DF56T/nOWm0e6sozA2C
         OQjKybwDksXZYRVoRIu+L2Rf6phrIys03ICHKebifJEgD9GP0hPSNtRRgdyxfNPyBf4o
         3/IA==
X-Forwarded-Encrypted: i=2; AJvYcCVD3GiXXB2gFk/P+Wj1ZpE2hIDWQiNxyfJjhZ4MTJuVlic/ePHiFzdzUryVIN6/AJmn9nvSyg==@lfdr.de
X-Gm-Message-State: AOJu0Yw4m5GNaOCE4HG+VZCGbMFdeZ+dY7daQdhgts35Q47bbuQ0p3s8
	k1V5oYsNMCcpW9sBvqCfsidH6ggsSEyGbNHpq/K1B15/nL76zfCoYpJU
X-Google-Smtp-Source: AGHT+IH6j+QtqKQziLmJ31ehggc9uAEN7Uuc1DG3LnRBEXzxcX+pcsvBBr6O/MOrck/cN+Tra+0Mew==
X-Received: by 2002:a05:6e02:85:b0:3e2:8ddd:b406 with SMTP id e9e14a558f8ab-3e4161b1ebcmr142529145ab.17.1754311422014;
        Mon, 04 Aug 2025 05:43:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcRJXx5rdaGwddaf2us4A1IFvkGuUX5e0Qg3YmFopV8dw==
Received: by 2002:a92:c266:0:b0:3e3:f406:c807 with SMTP id e9e14a558f8ab-3e402534c04ls48571095ab.2.-pod-prod-05-us;
 Mon, 04 Aug 2025 05:43:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUAYTZhdymfirMMDaFg0MBAd7l51twRY3cXHhKk3Cs4AnKibBf96j61ixfE+Wh6Q1eiQSNQ2gh2mSg=@googlegroups.com
X-Received: by 2002:a05:6602:1504:b0:881:8e2c:9995 with SMTP id ca18e2360f4ac-8818e2cb4cemr113628339f.11.1754311420941;
        Mon, 04 Aug 2025 05:43:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311420; cv=none;
        d=google.com; s=arc-20240605;
        b=VyK4cALgYF2zPKY+biJ0ApsPieLTGOP8+nb9k31hFPm8b3qjk0lRWhf/S4CnLx//ll
         GKbErmHSi31zNV9xfgZ8gtuIqHfcGqFNoMtd3/iavaiw2LIlb01ucko18kXvhqXiyqkJ
         z6BefMfaxx/3SbpRsvGXx0xtrYG+q6ZN1GUBTfkzWHhM97sUszhRgE4rDSOm40ezSUAb
         NCrW3NQLSq2C8t0voZFKRcm2DRtTi7jDBjcekgOXgEzzAHDowMs1kzdql0ugg2eeg1OX
         g9fcIPx0DbEZJ8UQkXB/xfFeQ0R9RRpAnii6TvA/x6vV2wWpxkLPgf9Sjtz9P21NkP03
         wasw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Yob5vGImG9Fz6Q3IIoENTL3tAbucLWfbEG7h2+LdGFM=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=HV+RWp1l3oGfJVOL6vAnKgUw0JQPUpb31N1bhJZs0+kAjFzc+RYt8k+BZp47pkUO6y
         p8wquoWv2inDkJd8TsWFg9mntbKhzLEXmt6Vf0pRRJUU3V+w9sFZNvZvw3IPLyQjtWk7
         fkvMbKx90EV997lC+VaQ25LkPY4mLlSp15WpyDNh8faG0J11/xDTOIvWNwCIvQ+qxy8H
         ofvq9pcUMe5uTG7jjmnPmjOoKPP+Mu3H8HDDfcotIyh+EmgA2zqXDbY6IG6uHOm5QlyX
         T05auwm4xH2xboy9XTgyjK4DXwKcDtOcg7bXp+zIvCnC5Ho9id3+Zy9+hfKleTS7IyBs
         pLaw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="hwpc/2Lt";
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50a55ebebb4si460260173.3.2025.08.04.05.43.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:43:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 5EDCF4423C;
	Mon,  4 Aug 2025 12:43:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D6868C4CEF0;
	Mon,  4 Aug 2025 12:43:38 +0000 (UTC)
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
Subject: [PATCH v1 06/16] iommu/dma: extend iommu_dma_*map_phys API to handle MMIO memory
Date: Mon,  4 Aug 2025 15:42:40 +0300
Message-ID: <09c04e0428f422c1b13d2b054af16e719de318a3.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="hwpc/2Lt";       spf=pass
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

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c | 20 ++++++++++++++++----
 1 file changed, 16 insertions(+), 4 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index 11c5d5f8c0981..0a19ce50938b3 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1193,12 +1193,17 @@ static inline size_t iova_unaligned(struct iova_domain *iovad, phys_addr_t phys,
 dma_addr_t iommu_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
 		enum dma_data_direction dir, unsigned long attrs)
 {
-	bool coherent = dev_is_dma_coherent(dev);
-	int prot = dma_info_to_prot(dir, coherent, attrs);
 	struct iommu_domain *domain = iommu_get_dma_domain(dev);
 	struct iommu_dma_cookie *cookie = domain->iova_cookie;
 	struct iova_domain *iovad = &cookie->iovad;
 	dma_addr_t iova, dma_mask = dma_get_mask(dev);
+	bool coherent;
+	int prot;
+
+	if (attrs & DMA_ATTR_MMIO)
+		return __iommu_dma_map(dev, phys, size,
+				dma_info_to_prot(dir, false, attrs) | IOMMU_MMIO,
+				dma_get_mask(dev));
 
 	/*
 	 * If both the physical buffer start address and size are page aligned,
@@ -1211,6 +1216,9 @@ dma_addr_t iommu_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
 			return DMA_MAPPING_ERROR;
 	}
 
+	coherent = dev_is_dma_coherent(dev);
+	prot = dma_info_to_prot(dir, coherent, attrs);
+
 	if (!coherent && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
 		arch_sync_dma_for_device(phys, size, dir);
 
@@ -1223,10 +1231,14 @@ dma_addr_t iommu_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/09c04e0428f422c1b13d2b054af16e719de318a3.1754292567.git.leon%40kernel.org.
