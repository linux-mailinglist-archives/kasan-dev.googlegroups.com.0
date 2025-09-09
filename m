Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBAOXQDDAMGQEKOND6TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id DB1DAB4FCCA
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:28:34 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-40826edb6e1sf71022765ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:28:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424514; cv=pass;
        d=google.com; s=arc-20240605;
        b=hbi/RJM0P2D3x1sEaX22n06bKgd5rGWqisA/o1BsKot6xaTbyFotic+2jP0jAaGUQo
         ge0waN+Gci0YwHNuBKK33GJ7C88QnM/LD6MWsbWAP1pa0IuAR7MYyo8koLUb/VwJ7iHy
         y+hheFYeqAcDWE68avLo8urr369zsTGbAQmBKTRjwuCZJ3gxQw0fWw/MUYdj64rRPRMA
         O1A7cAj6hEpvq4s69Yv318fRYufLfTcmW9G6V14//TvxY8drgw21Bit9WEYs6Z1f8Ots
         m+8RpqVR6gbUiiNkVOrcAki5fQX4kP1ew7MxLxjCj4iQ4tA0tJAzbn0QIiZYZZeI2T+b
         n0Iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ga9LvwACBSLOwgjZ3MOhg5zZ/bA6XnPPt+P5WVsEBWs=;
        fh=HEkzzr5h3PfBNEMfWkxUISyGjnrO+Ag1AAtAG82Q4WA=;
        b=E1hFbNIw7tQzMR/H23Pz6VvEP0Pz2KjSD9JOmOQScfl8hBrwRdJQeHC4cxnAnFXF80
         3lZpJ6hSRrs0hQwLL30egHAeVXhdKfnGoS2eJZ0zH+BU8fV2pTdIRnz68Tpq0gm0QBu1
         XKUSZgr99jyJirWEYShSUsTl7VQ0k5ogaOMKxFf15z+wkeoXxnuJtrn0W219vJMMeiqo
         Kg6HD/vvLbkEH8LnUpF0byeLEPUsJncZ9MflKDvLfywL0cVRcYnjVUkv2dWymfL8PUiv
         qw41b4Od0jpDdUzz1he3+DpfuzYBFTbCXQMC9SQ0VrKRb0wun6mWutgCHX6SFzfKqzK3
         Ls9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tCpUTcP9;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424513; x=1758029313; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ga9LvwACBSLOwgjZ3MOhg5zZ/bA6XnPPt+P5WVsEBWs=;
        b=C0ACPSm6mTPWPr9A6/mpZio0wfgFkkdRSomFcDPRBNCndfrPSkPzkd974Ns+QP8XVn
         HICOgVUBTbYpipnyJbRcjlNy2aB0LFDchMlMFG6ajLk1xviFDvbwP4Lsl3I3PhbI9FEj
         /+Hf97qXenPPhTSmNtKDq5FPBvZFj0vRvIFUV/5kQqLAtbr6R+roFUC9mCwUHm3IFw8M
         FqHi9n2ykxO169/zE0WWKAEnieigFdG5gWmV4iQ8CtQoaaLge7Hd5LQ2YJ1LJFBx6BSi
         ctVrYhIQYDpiRn8gsLHVgqiTls9m+6jusYo436YSwUoTef3tFFaOXUdl5yCzRZKESsxN
         5APA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424514; x=1758029314;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ga9LvwACBSLOwgjZ3MOhg5zZ/bA6XnPPt+P5WVsEBWs=;
        b=uxoeiq0pHcMsdQiS6JMf8nyQXce7A17wZnIzTWcoT2s/DhVFPD6VlAyfpy9u848e/Y
         SnJS4/NqqiM26XyzCNAYuujqKKdQba4CwAY7rR+o67BNuYx1/r6q9KcTqssu8Vj/FzGp
         K6PuBzhe1XwOMLyi92uYkrr0R0mmjCwEAx44bJizy96qkWUSYxSlnUZyynSk5CpJzLtE
         GcVXa292ir9s4hZqE1xKsjvYKb+hVWtKp1FWEPDxWtYYK77QQtA4gqCfnol4ROVlp9Mb
         XYJMDdsowmfyWQQc4sIW9JjikfGUjcNL6vRsL44KRcwVCWJh2PG3ViodtWT3J9l+/2My
         E/5Q==
X-Forwarded-Encrypted: i=2; AJvYcCX79ZsTDS9J9ULyzxOJLbpsIbKfPC8JR+0ygusxCqin36CSdCgyViH3wR9dS8IKoQloNn8QyQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz/o/vGMDGX8jmMawdcuSdy9v48LbF1J0SCoPIaVltoDOznraec
	OhQ5QWP1Drviy6T0cKOhsJryPQqI8ryipgIvvwlmBoWiKwXoMIag8Z0r
X-Google-Smtp-Source: AGHT+IFdSHOsqqK2ZVCTsTx30g5E6lnPjjYng56NdA98vqLQ7+ouuI1KBCaOXeIVzSrQbJmW8UCpHA==
X-Received: by 2002:a92:cda3:0:b0:413:86fe:8ae8 with SMTP id e9e14a558f8ab-41386fe8b6cmr11936745ab.9.1757424513592;
        Tue, 09 Sep 2025 06:28:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd7iUMSu527Prs67/Vepm6gZmx5m56ltOvM5MXJXfkBsg==
Received: by 2002:a05:6e02:470f:b0:3ed:8be3:e759 with SMTP id
 e9e14a558f8ab-3f8adcb41d7ls43740725ab.1.-pod-prod-08-us; Tue, 09 Sep 2025
 06:28:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLzcwAQDxEJJc6Uee30yHhb44RDur5XyvsomXHWX8G+OSF8pjmSIuZgdXs+ZIC6rji3lEinJPWKKc=@googlegroups.com
X-Received: by 2002:a05:6e02:258d:b0:404:91cc:e02e with SMTP id e9e14a558f8ab-40491cce663mr117357455ab.8.1757424512488;
        Tue, 09 Sep 2025 06:28:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424512; cv=none;
        d=google.com; s=arc-20240605;
        b=R5GBtKApBcUI/cAp06WstUTWagSL0zTL6g/i0FSUlmJGKOHotZfY64mFoJQzwKDxXM
         YDDdsd1wkjYciNcz1YUtPlHCBhczyNMkMleXQ3pkSRJramT5HkttxzTouubZWSRt0ADe
         UdfJCPGgk4oia7/E9vAa+ZXDcrLQrI/v8+bdD55L9DK1KsC6//agk+kzD8isTbRTn2Ox
         PFUyxVbfD/jLntM3PBjJBMX1Zp+IDtMrB+pL2suUkXZAEddDditVeFOQ/msQ8LH1B5Kk
         eA7PB09cnCQR8HuwJ+C+Ar2QtMLRewcJ4RvAbUanK8TigwG+Zg/IXSUXf6VWNNy4W+kA
         6K5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1jDbBJ37dc+Sn0sIm6dEeCMOCCyfIxOldox5rGsCCSk=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=MrgcmIfSRBFaxYAezoDJdqKkxYA9ovJzvzFAWECMyvQHSU1T+3dMhKhrdfW3N/5cn9
         xraHtnNLZZIQeeB782LwFXHOdfBdUqGyq+5a1zGppbs/ctwPcdYey+z6iz0FueAZZmc0
         SnMTeGaMeT9gi1W/wf6vcu6KkWLFf92PkVHQRPYNvmBfBqWgU6mcFborDHET+jCK25TS
         ZUCkN0AqajKzXOavcaydqEoycLDc2HvlOm8YME6zlVuYYuh1YdHRSbMqNSxltaGZxMJ+
         Izo94M0EQWLFOHLiVHhAYljaKFPb/0hmlDEJ3PLP2OsBrhrJtvXqVa0DEswwFCEPK6AS
         Slow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tCpUTcP9;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4007fc6c9ecsi2731675ab.1.2025.09.09.06.28.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:28:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id D46A36022B;
	Tue,  9 Sep 2025 13:28:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CE634C4CEF4;
	Tue,  9 Sep 2025 13:28:30 +0000 (UTC)
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
Subject: [PATCH v6 02/16] iommu/dma: implement DMA_ATTR_MMIO for dma_iova_link().
Date: Tue,  9 Sep 2025 16:27:30 +0300
Message-ID: <17ba63991aeaf8a80d5aca9ba5d028f1daa58f62.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tCpUTcP9;       spf=pass
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

This will replace the hacky use of DMA_ATTR_SKIP_CPU_SYNC to avoid
touching the possibly non-KVA MMIO memory.

Also correct the incorrect caching attribute for the IOMMU, MMIO
memory should not be cachable inside the IOMMU mapping or it can
possibly create system problems. Set IOMMU_MMIO for DMA_ATTR_MMIO.

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c | 18 ++++++++++++++----
 1 file changed, 14 insertions(+), 4 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index ea2ef53bd4fef..e1185ba73e23a 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -724,7 +724,12 @@ static int iommu_dma_init_domain(struct iommu_domain *domain, struct device *dev
 static int dma_info_to_prot(enum dma_data_direction dir, bool coherent,
 		     unsigned long attrs)
 {
-	int prot = coherent ? IOMMU_CACHE : 0;
+	int prot;
+
+	if (attrs & DMA_ATTR_MMIO)
+		prot = IOMMU_MMIO;
+	else
+		prot = coherent ? IOMMU_CACHE : 0;
 
 	if (attrs & DMA_ATTR_PRIVILEGED)
 		prot |= IOMMU_PRIV;
@@ -1838,12 +1843,13 @@ static int __dma_iova_link(struct device *dev, dma_addr_t addr,
 		unsigned long attrs)
 {
 	bool coherent = dev_is_dma_coherent(dev);
+	int prot = dma_info_to_prot(dir, coherent, attrs);
 
-	if (!coherent && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
+	if (!coherent && !(attrs & (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_MMIO)))
 		arch_sync_dma_for_device(phys, size, dir);
 
 	return iommu_map_nosync(iommu_get_dma_domain(dev), addr, phys, size,
-			dma_info_to_prot(dir, coherent, attrs), GFP_ATOMIC);
+			prot, GFP_ATOMIC);
 }
 
 static int iommu_dma_iova_bounce_and_link(struct device *dev, dma_addr_t addr,
@@ -1949,9 +1955,13 @@ int dma_iova_link(struct device *dev, struct dma_iova_state *state,
 		return -EIO;
 
 	if (dev_use_swiotlb(dev, size, dir) &&
-	    iova_unaligned(iovad, phys, size))
+	    iova_unaligned(iovad, phys, size)) {
+		if (attrs & DMA_ATTR_MMIO)
+			return -EPERM;
+
 		return iommu_dma_iova_link_swiotlb(dev, state, phys, offset,
 				size, dir, attrs);
+	}
 
 	return __dma_iova_link(dev, state->addr + offset - iova_start_pad,
 			phys - iova_start_pad,
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/17ba63991aeaf8a80d5aca9ba5d028f1daa58f62.1757423202.git.leonro%40nvidia.com.
