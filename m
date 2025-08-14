Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBDXO63CAMGQECXRSVNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 25564B2620D
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:14:40 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-244581c62fasf7860025ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:14:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166478; cv=pass;
        d=google.com; s=arc-20240605;
        b=DkVUlXsl68aXykwOztawimL2TlBwb4v0JMKaxdZpcmcNOaWmCmmBYyca3XTE4hEnlo
         nK2MTY2dzi56j2C/JnLg9HCdmRZH6L+/SV0tbWhDM17hDPFAgSiVT5IlAotECHlhOpqo
         6ZTFJmZUxEHI3ih8mefDvZmibofIoD0v1mmbkec+WbMYB9RLxFJkuXOht8Bfk7IUCnIA
         /gdudCzz3kPEo530vRmXgXMyGL746BL2fwQ40xOAEd04k9+Wml88Hzb8Tab1rO65XKX+
         z9yHD1mqo1FZuK1BZnEHB97zW7CthriUNdql2QPo34SHSrqgBg9ujAKPukQKcKFj9Mm8
         M8Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=80HQDJTpH554EK5/fViYPlyI4RvBKzluhQRI0fJK/Ss=;
        fh=az6k4qAcWKjzxR8qcncT5Pt398w1wPYjbNJPzD8dxK0=;
        b=NVycE+d//hgkmx6W5OnqF55JlNjYrqLWscEEZEB7VCOJ5nD9GINHPDNjvx8WBmoyZN
         FtBqCkGJ/bK5/O87bbr9wi3g+rTsT7/rxJvrPlvdg5j1Fylef+xoQGIHgiQI3daqqPLU
         UjPVdmkhYBjAdZ4BpSkyZA6r/ONiaokF6+hoKyoRp0UGuhCjuyiB8qOrPsI1LPUoW3nf
         sFwIylTdmwkZOxZjzB4WuQJmTjL3JcHpny1xdLvW+do5NATlE1I821b1JeyU+P/XeVxN
         ZBELJxsLCXd8DbFqjolnSNJCljIPmL+41+YUU+pnccSBF3+hGwIqqXSfvn1usQR9yKKX
         a0og==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aVubZT2u;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166478; x=1755771278; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=80HQDJTpH554EK5/fViYPlyI4RvBKzluhQRI0fJK/Ss=;
        b=Z9qzulnsbWdDJikkZl4P0WtTxyENbVNkT3Onh2hcGXznNmiTNjEH4d4wsMdSmdi7Ic
         +cCSSCa6yVr7LWsl30mb+Tj0gavvWUx+dFjC6oFLCkbgIbAXJ8BuaIQD/U7mmVq8parr
         w4NcFDbvgigv3jL3lgFFbN7MQjf4G3L4v2DXaSRnsNenHF6yTLG+ss4n1EViRoANTfRB
         OvsU/fIaFarBq7/M/3LMs0ntVIDP5DbHJdrwBbVUKhj+EmSRFuoUHCGTa7RLvJuby/HN
         HT9NBCWFkSIXqk8On7HUB0iAqVACnzLEKtrcx7khIjdWjxAhA68Jts6ZqxLxBgBq7Lwf
         zhuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166478; x=1755771278;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=80HQDJTpH554EK5/fViYPlyI4RvBKzluhQRI0fJK/Ss=;
        b=fqV5aNO9nsfSWiAs5ArqLqX+KxGfmRoqGmwSEzcXHGaHsmzm4VtGtD6dDolzD0knvk
         8m9HkWAk/02UlIu6Yc6edgPlFJGoB7hakQvUBAh3nY/TAGcM68ds1KrQklt5FvRSuSfR
         EsdRSG3k30gic9ywk1uHOc/lpkQmtGlPN8sWtLxiUgkdhatTaQOdAwP9OpFB/xokC1Xc
         IklEXPFdI2GIHLBvx3rghYQBWChk2rcxL4Mko+Lly8LOi2nRb7n/699KFzs+uZjmOU/q
         tDKpMS0n3H5Oa6xJQmQE8EGOXob4w93GOmqmQ0iHi1ur0K2IV42q4/pSTQ7IQ1Xt+NMB
         83pw==
X-Forwarded-Encrypted: i=2; AJvYcCUUnXrRqD11aDSgWOxuzNtpEE8dYaeddgv6m72dXYyUDx1wGzXfEs1wPQeIDiWkUYIbmIUxkQ==@lfdr.de
X-Gm-Message-State: AOJu0YxJpmwYHALkZeqbGMIjZRdjYSspxxsfu8gboAgV8x4X3EKVk5vL
	dyP+nwNhAMKutoM/pg4FlV1eKBFYQhG+RipBreucnOCAVhXp011y/FkR
X-Google-Smtp-Source: AGHT+IEURN6nWoBtVlpMCPkPk5LwhCM4y0oMAVfFEGuMVkw3Qv5eZdlMgOMwjtYAqLw4ND+HtuvNQQ==
X-Received: by 2002:a17:903:b8d:b0:241:ff36:552d with SMTP id d9443c01a7336-244584c2634mr36953065ad.1.1755166478506;
        Thu, 14 Aug 2025 03:14:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfCN5FhDhgDpx0qxQyUGq+1xlXEzmDm0tiEdYLIUZqMpw==
Received: by 2002:a17:903:2ec7:b0:234:e655:a617 with SMTP id
 d9443c01a7336-244575aa9f7ls9018945ad.2.-pod-prod-02-us; Thu, 14 Aug 2025
 03:14:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUIszSsn7ym1UFQLvN1tVj9E/SjHQIWF/bNExDptNX4lfZ0HlhSBhM08nUJjuqmGW0CrAMzyXoEUHc=@googlegroups.com
X-Received: by 2002:a17:903:710:b0:240:a21c:89a6 with SMTP id d9443c01a7336-244584c2d98mr27991275ad.12.1755166477173;
        Thu, 14 Aug 2025 03:14:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166477; cv=none;
        d=google.com; s=arc-20240605;
        b=EJYSQSsSlg2UqQbK+E7m0g/tgERjpbSllL//qk5w63qB4AWpyApG8VZv2l9JtnoVHc
         Yvj1k7Mr1SWeJKzYweXsr1r9VqKz8y7IYn1BnsJpjZGEWnWf+bki0oLNv9XWS/3oDvsz
         dNc2TSFN62TpYavRpNGfksSjaejbyN+omdtKLe5x4Ea7qBChyAEcndg3Hl20cM/Sg2kK
         W/1alaj9kPOBeYF1tgiorIwfwCxQ5OLSJxc6FiRS3NdYENXLFHtKLnlke0eAAES9Nrob
         RuWx2GbQlm8BQzHIzUSQVbofQopzCnkx4LbUm/mzXZwFFO1fY6mIGOmTTJjLx2aOXJ5t
         iiOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=W1NCjZhyl27tEG0V7+Bnhq6xk8+QM26SXgxxy0a0etE=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=KNMljF5ZxbiRrAeK1gjv8L4kMDI454YYBwccLe/v66BidLZKZ/LwXKoYd1RnVbwUes
         V5jVD+J8T7VX8r/bzxOQJxaayw+u8H5qC3Uowf1FZiKgoy1sy9eQm5rSND34GYA+nrfW
         qAwygsaNdz1zhbz0mSvvChlJhDk/htTJaJWlEA5PUzA5GGjdEb24+IoflvSBjcrHeMGb
         oOIFWq0htS+vbN7zlWdufkLSPCu0lQmcygrljorikN0cOxKHzOlZXUdS1Z5jN4Y1UEwl
         7no0lZ3nENA6C1jb4hKoRPUHVrwiJw17ZkzPOwmtg9eydOlr9CiHBotxBRlxuL8mVsMU
         juRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aVubZT2u;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241d1fb2627si16034965ad.5.2025.08.14.03.14.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:14:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 41027A56685;
	Thu, 14 Aug 2025 10:14:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 20789C4CEF7;
	Thu, 14 Aug 2025 10:14:35 +0000 (UTC)
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
Subject: [PATCH v2 09/16] dma-mapping: handle MMIO flow in dma_map|unmap_page
Date: Thu, 14 Aug 2025 13:13:27 +0300
Message-ID: <7b8c8f88f61c85d60e24f04e88d42357b898ccbc.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=aVubZT2u;       spf=pass
 (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted
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

Extend base DMA page API to handle MMIO flow and follow
existing dma_map_resource() implementation to rely on dma_map_direct()
only to take DMA direct path.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 kernel/dma/mapping.c | 24 ++++++++++++++++++++----
 1 file changed, 20 insertions(+), 4 deletions(-)

diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 709405d46b2b..8725508a6c57 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -158,6 +158,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
 	phys_addr_t phys = page_to_phys(page) + offset;
+	bool is_mmio = attrs & DMA_ATTR_MMIO;
 	dma_addr_t addr;
 
 	BUG_ON(!valid_dma_direction(dir));
@@ -166,12 +167,23 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
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
+
 	kmsan_handle_dma(phys, size, dir);
 	trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
 	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
@@ -184,14 +196,18 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7b8c8f88f61c85d60e24f04e88d42357b898ccbc.1755153054.git.leon%40kernel.org.
