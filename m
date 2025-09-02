Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB2EH3TCQMGQER34OEMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BDEFB4078C
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:49:14 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-24abc029ee3sf27665885ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:49:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824552; cv=pass;
        d=google.com; s=arc-20240605;
        b=HiW8QuKBZBd5f6dkk3kB3KDrowWuY8SfzsAegzkDiPC5aHvpftEP1BP4K+oAn4M589
         ZRKgUXHDy3Y0CTQERdUENZwXoh9l/RxW/AbyPC+R+JMV0xtDd3XbYr7aO+ZxToumIkvH
         tXA/RhvT7WKsO8h1QN/7yYjJ1hEzh9A7BeseE7wGPfe1qKRhJ3sFVDaVM7P3c+kxc66g
         MFRivBxbza+TLy2x+NhC5z7s+QNdflX2JyFVfpdZPoftdC+URm+77yqNZD7X2OPCk0iX
         6phtgJS/32aVelg+2vaoZCR01EyiJ8FgR7A9TIpdxEBbwMp2pWLSOuzCtKm25p7HJTEH
         firg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=L+91gsUSjH0KRLwElnAEbiOAUJnyN1K3BmmR/rHWjyo=;
        fh=+7eL9/hZdN5x12GBTWgZARDFMz3H4qL1yA875fA521Y=;
        b=NhKj04i4u0F1gbp3RUPeZj82uY1GCqEN7kfs6T7B0wp2+mRwgVcL2ThKQkzeHDJeTz
         FjaJ/+24yGVlc6mNvOFDoagR84ud48yVsKTGQZPIE14VmUHuWL/Ehglj36YorUKz9pXM
         DweFDjMnx6x6i6qMUrgjEbl4ws9QJUDI9vwz8L2ArOnjaQMdJcIDcRpCWos8A46vxdhS
         XRBGB3n3pNGvVQpuROQ/xJKcNyg4uabmbDgnsTPj0geyVKAv8O7LIrvsJ3B8uGykZ73b
         7bo50/kKkQhcUhZxnC8YkH86i3YMCs8L6o75LgsLHC1wrbWEPPSSm0NlOFfOSL7UTpNB
         BRVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=U0Qv8COD;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824552; x=1757429352; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=L+91gsUSjH0KRLwElnAEbiOAUJnyN1K3BmmR/rHWjyo=;
        b=ipbBTVqj/jTHyN6vL38FRKnf8vqBdUgPd9lYpnG7oZGqDXLhclHwb1nLHGlKjrZQTm
         AKKRpOoaOIRpsGwl/Cu+RP7HSHXnG09wI5NYuePWkYERaTmwlEsrMMILoglAH/T1Ejup
         pKZ0UGcSIWybzRE8tZ6eomPcV1ko4jX6zv0hw0nlQLZrLxZTPfhr+Pv8bQKO/eHyIXjo
         rPE9FvFGsMv19z8QoLFkEv3YvXfU5KwgeVCA0tf+nWMWCKEfAjI+Ecvl1X99jNZWzq7w
         bHvx7BYkb2SKYzR47CsF9CbkQ5bev8O55LrrBOU+glxq/PU4QNNiUhm90zv3dAQ6udtP
         HRsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824552; x=1757429352;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=L+91gsUSjH0KRLwElnAEbiOAUJnyN1K3BmmR/rHWjyo=;
        b=svgQSsx2slSN9aKxbg7ymyiay3lsIjuGrKWFYi6DD7BEYPQhz9osXEvLHERwEklFA/
         kV+1owqXlYYQNM3CBePwKfRrrgxTmo2XSIXwrNLWHQNNdcXAwQ6FzNwJ2CAAkx1Sp6NJ
         icYicrhc7TiE0QuSG+Kv3tTXSkBnqyx8vhwlKz8PKcDi3Tipv78H5KIVL56CMgq/4GIB
         /wVjmzbtzOSE/PMQtOsA6TCqAeXFVoUO4ZLns4ZGjE8FpgqIVOmeoaGRBw365AbN0v29
         Rm5rLNTyxXPOiFGsRbun9pnz943KTrI/Zha9126rVL9xCLE8CCcbALU1jgusBA2vK+am
         QbCg==
X-Forwarded-Encrypted: i=2; AJvYcCU0UuxEhLJG8NX5dwFkgNtA3Q4YDCii2FpiLcPSjLHyiy76cdU8BexnF3okKN+/okSpoiCN1g==@lfdr.de
X-Gm-Message-State: AOJu0Ywu7ZPL46JMYK3MCRKo54CmGP9qUeE55txvSnYTje3TWknYAjZQ
	vRb8oQCojrqp6FRmB+WY2iqR5Np0hDLtgcjsj14SZeQClkyNyICKcLQl
X-Google-Smtp-Source: AGHT+IEPdECQ6EeSsOGuVzVHUgMpwO0qrWHLDc9H8KjuxpMnjGyXCYaHFkYKLGv1lYY8QAiowaftiA==
X-Received: by 2002:a17:903:28c:b0:240:3eb9:5363 with SMTP id d9443c01a7336-24944a70227mr166401195ad.27.1756824552531;
        Tue, 02 Sep 2025 07:49:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfKdfL6H+i8M6dkeHtoXMnswPlKk5emlOytZ6cPzEFqtg==
Received: by 2002:a17:902:d590:b0:24a:990b:75e5 with SMTP id
 d9443c01a7336-24a990b76efls32743505ad.1.-pod-prod-01-us; Tue, 02 Sep 2025
 07:49:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTAKvvowZKTxGByTf6y4ZzAJGwHVTHDQ1Cj+tnvjICzBoYyZh7+z8YVThJtqScGSALgNR+SEA+4K8=@googlegroups.com
X-Received: by 2002:a17:903:28d:b0:249:2c40:51b2 with SMTP id d9443c01a7336-24944b8143dmr156702425ad.59.1756824551151;
        Tue, 02 Sep 2025 07:49:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824551; cv=none;
        d=google.com; s=arc-20240605;
        b=GRzPTmdKdzVMHLyoWHMM1QPTtT6xwTLs9Q3O0+DXLkSPJlvrxAoAhphr/ArJOOKj48
         bGJyAnz6q8oCbSSz8WhQZTiot1Q0NoEtfz6Cileb/uCjfidLrM3X032cSsDV7zMMcNej
         TMwo5jhqiDg/yfAMXcrqA9hDAbHROjkhuNVWz4oBnRhkUekw5p7yPx5u1S+GAd/SaXrR
         AwiGrhNcgyGk30ilwJnJxmJbyus02G4Q759wCjrDFBQMtvwpPd9/98n91Fd45JnVkmt/
         /G17LqOKXZm7l6W8vHbCloHEuzWLw0Kj5RIju2CCk+jBWZxC+i2q9ipdLibLUBg0Aitr
         R9gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KfgzUojTM/DB/MYkk7DA2Hi+SCW1x3wlstgTHhLqb3I=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=FpGW6aDy5Kel2bcXo/tXOSRV5i7Z2gwI/p3fG2qSg6aXEPROnnIQqIsTAhq4VfnUdx
         e/DzR53/lTtWc+VZmtPZHh7xhp2xl4yv0djHwGY2kLo3BW6uZ1XpQoWCaFxoA3M2W24x
         uKH7/qVqV9JRxwJQ06eGRPsd+Td1Hma0UN0FtEKwRqTNZDqEeQD+cJNyDmkkGcwHcrIf
         bBhgB92XREYe2B1Hmq5V6pVU3k+1Vt9DxBCDa9wc5yHTRm2BM+E+p+EaHok/8WgAi7g2
         wJLWbmIevAohYnW6ReX1cg+XkM2fzicPfC8Dy68IfuNypPpbulVdd8d8ynyIAjy/zy/y
         sPug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=U0Qv8COD;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-24906395a11si4391745ad.6.2025.09.02.07.49.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:49:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 272106021C;
	Tue,  2 Sep 2025 14:49:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2C5C6C4CEED;
	Tue,  2 Sep 2025 14:49:09 +0000 (UTC)
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
Subject: [PATCH v5 02/16] iommu/dma: implement DMA_ATTR_MMIO for dma_iova_link().
Date: Tue,  2 Sep 2025 17:48:39 +0300
Message-ID: <5a279b1ce492ba8635eb3fa6bb9a22fd77366672.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=U0Qv8COD;       spf=pass
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
index ea2ef53bd4fe..e1185ba73e23 100644
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
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5a279b1ce492ba8635eb3fa6bb9a22fd77366672.1756822782.git.leon%40kernel.org.
