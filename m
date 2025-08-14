Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBFXO63CAMGQEJWQTAUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id D81B1B26211
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:14:47 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-244581953b8sf9341095ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:14:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166486; cv=pass;
        d=google.com; s=arc-20240605;
        b=OpYKR88KGN9A0JVc+8GhgaZ0qHB0EURR5dk98qkEgKCYHXwrbGZhljebS+7WYEJzVP
         xEzA3MkEKbUkAbanbp1b1L6t3s0l9kWgEMpQkxGeZ20lxTdmJcik3N9rRT4HPUVN/pwL
         m88+gKaGkNLMR1mZn4v9ippHiGn3dED4GQmvmIsNZ0fS36pIvRgTKi125jVOTCPl1pSv
         YddkyNcv9+EzdasAmWiue2LSqPbdgvA86UdGIDq2EQmpi6D+snj895B9vF8k3ufSOD1t
         Y0hljJFpEtDMNQCEazhq39RmZq/D6xmxr8bO3/8svMijS/4pEjUmeCsV03EP9o7GjoKm
         3Ucw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=VmLkWuNmjc8qx6qyxlRG2dest5VCBwcBu67lcmLH3EU=;
        fh=6jZQHa4GCuSW/ns5o6idRBwvoS3KCwcpYWhbtEvGnt4=;
        b=hRnamn1Nbi5H7Tk1HVEHtY9PJrvXe2F4f02FygJXAW+m+YzG2kDbvEmPShiyoxtB+/
         GDt1C7EfktCCBBOs9SZpCuie7aohRyM/07oal6l2UGU7Jmz8TMhrzOiUdHWnAVC0TeZT
         djWFZQlC1J2cgt0L1K4iUq+KZ7KCIFCF071CXGJ/nns8W7JcyPHpa1kDX7K/TRghTwRt
         jQ2Xs48IUUn+gWbD3BxeW/xqj6LITkl+MdY6C2X+bYervZ3zoMNkiVvfWvJObNcr4mIt
         +Vx5z2aMs/4d7YkRCa7GC/PgJr13KDnoqGgoz9Ftp5JIvLazIbaV1/OHtA8muKfW+saN
         zwVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GOIGZTAL;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166486; x=1755771286; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VmLkWuNmjc8qx6qyxlRG2dest5VCBwcBu67lcmLH3EU=;
        b=ZRTplcryIxnikSnwEXdHdGr1RQdWSWPzQ6egNnqZ0KLKo5yY8hqiV0iAE/LBAwbutZ
         Z1DRPUtO9qR00sW75GfHD6M2R8quIeoAKGnpH9Mdwi7sQfxVR3Pmz4qjoah+AHY2Bekj
         66iRzC6vsxZ1QBn9z7iSMxPJOr6djya7p9D/puqJDkzlJt+S2Z04qCw8vRTHXvcqjxhg
         6XI90xz9l5sTh11YLBjLHgZm+vxujoXiT8ylFU4wvkKx2AwETe3NPo/agIbnZr+gF22X
         vZnoTyJJ0utrcbykZ3wmebC+VlnflRV9AR30Ii286Uw7LxS00Yizt2dvD9irqbBcp2E4
         ezzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166486; x=1755771286;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VmLkWuNmjc8qx6qyxlRG2dest5VCBwcBu67lcmLH3EU=;
        b=lHPZJZg2AylmYWYE2z7+Z1gPJfMTlBnfWBR17RkdhhmHPYmmy0C7wYp5fLPtrhXbfE
         Qpn8OhJV9S2SNBAYgC02qyD+5DiarMAKheNOIHkNODzfsbMyjvl4bAatAAn1OirL5cUt
         eYhVUDuaARQgrFCBGFpQ9tEyNaz1BF4dSYg7Tgf8LcRszfeMsnORbyc79uisHLONZp6H
         heB2iuqhzom7O7pIpZyM9pFWaaQV2QhDR1SDEJnn0WTEOOr2dcUQi1x+qx5Z2pceJa2v
         JRUD+EN+zudpYhOftBCNysH6bpWpo+C+fZ1EZt7UIO/eRekoma/TU+GOKBgAD18/n3Ur
         4AYA==
X-Forwarded-Encrypted: i=2; AJvYcCV/F5b3JV7EqGGayTauoDaulC8kIrubguLT0QDW/5gt+VKXc6NkhiNXwnz+RLTvEwBHNbTAZA==@lfdr.de
X-Gm-Message-State: AOJu0Yw70z8rKaO7hiV+NSg7IkRFAfQHpJkmTzhnkV1nNk5a18hJwDOs
	KjPPU/3RrifiUzyq4Cj1T3pEKVo3lPXqmt36YtkLEAYx6132Za2pbOV2
X-Google-Smtp-Source: AGHT+IGp70SURwiDkbRSn24FEGhgmY7xNxxjeBVthDYy679527EsTaV/gsz7ZhMO5LvEnvh5wRP27w==
X-Received: by 2002:a17:902:f70a:b0:242:e0f1:f4b9 with SMTP id d9443c01a7336-244584f4d8fmr37864055ad.20.1755166486457;
        Thu, 14 Aug 2025 03:14:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcfaXskQyxEo4QFr6Gk6tQegecg/A6Vu/fWWr0SzmJ39A==
Received: by 2002:a17:902:f64d:b0:235:f4e3:9c7c with SMTP id
 d9443c01a7336-2445757c117ls7704225ad.1.-pod-prod-05-us; Thu, 14 Aug 2025
 03:14:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUtuuYCR0e++8XLLtO1KzvdZG6EzecEr2mfGfnLhBJ9p7xHpFVkebW0gCTx5pyoUxiGRrxp1NiOPs0=@googlegroups.com
X-Received: by 2002:a17:902:c943:b0:23f:ecc1:ed6f with SMTP id d9443c01a7336-244584da3fbmr38990165ad.17.1755166484937;
        Thu, 14 Aug 2025 03:14:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166484; cv=none;
        d=google.com; s=arc-20240605;
        b=Hjnz8Nm3PBb4dP5LrqhF9EYzHGju/OBT1n2u/4kylwKxZj6DRttuK+yYAJoa+05R14
         gFWdEVzJxVcfNHWGbI7U6tIFlxS3SiKfy79ptuflijfXSsylga2S2I1i9gtyrmM8hwtK
         5a9JbwigWcb/SjslW6j+wR5h/O2jIXxmIzzaXzAGHxFDSFWZKdpKjO97lTPA2rZdvP0/
         dNOtyBM6VFJbNdAAAAUxJ5QfVANZKrlJtM1WtZD6wy49iHssqjWMuIHBOCO7BkpMyoQa
         oaaJUdJr3AmRxXMNLCsed8uFglX/Zd2n4vrou8JZwZLVkalA7gw2tziJvyXhil0CtAbN
         k3Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=D4SM6zHJ9Q6ObBfi9kz8op3wvjKvHEZA6J8C6N7vBkM=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=JGSxcyPd+ZIK49TO96jbFGGcVJq95uy/pfv6AvAuB7Idi12Tzfkd5e/96uKo1VmXBr
         vUL1TAFiCj97gIB/9t68kGKlvTTMgerODvX9Yy1k2OTA4w1K4ds609D+in+8Zpkzh8/0
         f0jrGtV/rElNtZppqdqOKNrKrlDxH3YAEF/JXNeX8s61oD8UBBHQwMBglkcL9y0ir1/Q
         wwo0IPnx2AlypfvMSZl/swP3oFYXeCTS3tCla1BS4ub1q/JWVltnkHdpAObj4ABBpd9i
         YcIzCOhJXveuFcPbxgUFjjAZEf+7A5SKrZYE56JYxGt/PWlKuXNg2Snj9zA9uOIBa5Cv
         ZE9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GOIGZTAL;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b42a1fb15cfsi584209a12.2.2025.08.14.03.14.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:14:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id B7C19435C3;
	Thu, 14 Aug 2025 10:14:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AE2CAC4CEED;
	Thu, 14 Aug 2025 10:14:43 +0000 (UTC)
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
Subject: [PATCH v2 13/16] mm/hmm: properly take MMIO path
Date: Thu, 14 Aug 2025 13:13:31 +0300
Message-ID: <1c5a07cc7b40e956b2d75328fc95e45e82d2da5d.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GOIGZTAL;       spf=pass
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

In case peer-to-peer transaction traverses through host bridge,
the IOMMU needs to have IOMMU_MMIO flag, together with skip of
CPU sync.

The latter was handled by provided DMA_ATTR_SKIP_CPU_SYNC flag,
but IOMMU flag was missed, due to assumption that such memory
can be treated as regular one.

Reuse newly introduced DMA attribute to properly take MMIO path.

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 mm/hmm.c | 15 ++++++++-------
 1 file changed, 8 insertions(+), 7 deletions(-)

diff --git a/mm/hmm.c b/mm/hmm.c
index 015ab243f081..6556c0e074ba 100644
--- a/mm/hmm.c
+++ b/mm/hmm.c
@@ -746,7 +746,7 @@ dma_addr_t hmm_dma_map_pfn(struct device *dev, struct hmm_dma_map *map,
 	case PCI_P2PDMA_MAP_NONE:
 		break;
 	case PCI_P2PDMA_MAP_THRU_HOST_BRIDGE:
-		attrs |= DMA_ATTR_SKIP_CPU_SYNC;
+		attrs |= DMA_ATTR_MMIO;
 		pfns[idx] |= HMM_PFN_P2PDMA;
 		break;
 	case PCI_P2PDMA_MAP_BUS_ADDR:
@@ -776,7 +776,7 @@ dma_addr_t hmm_dma_map_pfn(struct device *dev, struct hmm_dma_map *map,
 			goto error;
 
 		dma_addr = dma_map_phys(dev, paddr, map->dma_entry_size,
-					DMA_BIDIRECTIONAL, 0);
+					DMA_BIDIRECTIONAL, attrs);
 		if (dma_mapping_error(dev, dma_addr))
 			goto error;
 
@@ -811,16 +811,17 @@ bool hmm_dma_unmap_pfn(struct device *dev, struct hmm_dma_map *map, size_t idx)
 	if ((pfns[idx] & valid_dma) != valid_dma)
 		return false;
 
+	if (pfns[idx] & HMM_PFN_P2PDMA)
+		attrs |= DMA_ATTR_MMIO;
+
 	if (pfns[idx] & HMM_PFN_P2PDMA_BUS)
 		; /* no need to unmap bus address P2P mappings */
-	else if (dma_use_iova(state)) {
-		if (pfns[idx] & HMM_PFN_P2PDMA)
-			attrs |= DMA_ATTR_SKIP_CPU_SYNC;
+	else if (dma_use_iova(state))
 		dma_iova_unlink(dev, state, idx * map->dma_entry_size,
 				map->dma_entry_size, DMA_BIDIRECTIONAL, attrs);
-	} else if (dma_need_unmap(dev))
+	else if (dma_need_unmap(dev))
 		dma_unmap_phys(dev, dma_addrs[idx], map->dma_entry_size,
-			       DMA_BIDIRECTIONAL, 0);
+			       DMA_BIDIRECTIONAL, attrs);
 
 	pfns[idx] &=
 		~(HMM_PFN_DMA_MAPPED | HMM_PFN_P2PDMA | HMM_PFN_P2PDMA_BUS);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1c5a07cc7b40e956b2d75328fc95e45e82d2da5d.1755153054.git.leon%40kernel.org.
