Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBJGWYLCAMGQEYCS6ZMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E30FB1A1C5
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:44:22 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2e933923303sf3628662fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:44:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311460; cv=pass;
        d=google.com; s=arc-20240605;
        b=dnsE1mTDRUO7IZrVULLBDygG+cvW7xMx0dB8S0ld64JRzyntZHqHzkh8MVS55nQB75
         tWJqgOcSef8Y5UTcl/G6WnNROVORqr0P0io0yF/rmUJA0uU6ugMm/9ptb45U1UiBzD8T
         EhQuKXpHuaw+pvvlkVl05GYi4lmZEH3TSAQPHJRA7+Jk5MtuNBeJvtJKvEKvJyX6Wp5Q
         yRnoXJtkOq4oPSEoRgj6qcvxUkP9gDSks6aqxrWmDrson6MQoRduOtPbuKLTle0Wgja+
         vn145mtd4I5B2Rni9uSowJtO9wzGeNn+uQo9uo0QO3SJJ5KKb6B6Cc+mlzxuwTz+bAt8
         gEGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=2BjIMNQVdOFAULeMg+3RJa4g2oBegYjZLt+rvdFecFU=;
        fh=nZZPHI/l6jhQz8ZoWrhQpNqHOMlBTJRrzldeaYRTx20=;
        b=U4lpQltNQtsxjSaqn64yAplScJ5t8WDOU3Qxbo5v7A1MA5PukKxOiuAuI88tvA0ETG
         eWQ6Vnu8DE4e+c5qjjZ8SYIFpgDRGCPNJ7RT1XeDy8iF2EBhZ+BXmfp21rd5CfAt24vw
         d6cFF6xaGcylAe3lXGE4yuwtkdXotHk6QST27ObdTXp8D98IS0/QhFCZQt9mNUiBuWdc
         NOmRBLdAoARVzyujTx4x0MOnyHSM5juPH9YeZm5dTKj+P3IVhth73rEnp+T5h3cMPLqo
         sRlfak7uH0KLFF2we6IWwZb17Nvzq5NZHR4BZEyp/dYua4DsBB9bb0+X76fXSe16wiFV
         x78Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=twziXknB;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311460; x=1754916260; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2BjIMNQVdOFAULeMg+3RJa4g2oBegYjZLt+rvdFecFU=;
        b=rp/r+3/RDB9VMi+8EuzzUrml+T3zdw5P+WBRy3flPJWoSBAOUFiB4HCMgwt2ZIRpXR
         T/pr0My+9v3n8B6amTDtlu1sKlTd/f8hXooxqrPFkaas5bRFHi4nmpTr9dhry8J/nh1x
         FrJT1ID5R2bZ/TgNNCMEfvRH6G1PNavTBU7J0d7b4akEO+7dJmS1RjXeUF6cHWZ8IW87
         iLV2ACGg8RAL3eLJL4gnOPbvEr/ltC2svSH9BBILngfczQLfyLK6A8Gu+Pv8y/GtHVz5
         dSEnVw5AqYO0l8eCORKrIn8XtYCCNpYkkbqMBcYRPpCBxhaCQlxlxVsSpOIq6U07mFfx
         c8oA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311460; x=1754916260;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2BjIMNQVdOFAULeMg+3RJa4g2oBegYjZLt+rvdFecFU=;
        b=lWPmQ/zzUyjarocf7BPjsEP57m4t75Sq67o86EewuwtyxzBYY+s9I2CDYH0Hk9P7uK
         t7zAlZscMrAmuOoahBolyLxYsxclOkV2pRNK16/bOK6I5kJB7+9e93CE8ljVWqzlFaTA
         graF1CxSLyqPtdAD/G+9r1PYfgkIQyngHafMT+ZSc2YTC7x16Jzdotsk5C9yn0F5WO14
         HlPJK+eZ3F015/qzD0KKcOpHNNFpdZmUcxXiRL8+Ko4bkEqhuaXchxXe1ulmRn1cI/YW
         859pSfp5k56Z78+LZKnOgoxHLfPWvZ1EE/LrRtvxswmG9WLO+RK1IPqHAmdN0fo3vFv9
         Tj6g==
X-Forwarded-Encrypted: i=2; AJvYcCXNQfN0Cyk5bJOtWd4RVcEYDmG4DT0sSg2nZVW7bUApm7hKOkwjkFhOH6ms9Q43xHaW1OfKvQ==@lfdr.de
X-Gm-Message-State: AOJu0YylyTxcg7uQgSTdkUGQ1sh1eh/o4/Crp1hC0GqYK0AikFHVDKc6
	tY9TuZ2UkkoXI+6XJhxDBuvlKd4K+jPO7nIp4kgYf1+rL2Fi1hDk4fDc
X-Google-Smtp-Source: AGHT+IEerzMQRE++jErnzAsSdUivPC6Wl8JX+UQDMso59DMOqVBfgkR9Mz+l3Rr0rjCHduFb/dj0AA==
X-Received: by 2002:a05:6870:b207:b0:2cc:4613:76f0 with SMTP id 586e51a60fabf-30b67707f0bmr4671048fac.17.1754311460418;
        Mon, 04 Aug 2025 05:44:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZduP+PnvXEwIy6nbv/YyZWWMgpR2E1q3e3jwX+FYEQ23g==
Received: by 2002:a05:6871:7296:b0:29f:aff3:65c8 with SMTP id
 586e51a60fabf-307a76b1d2els2427362fac.2.-pod-prod-08-us; Mon, 04 Aug 2025
 05:44:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU8Ex50oyIk/byARCnn+c3MAaegf4SfdCwCmLf217RXqU5A9DJOkkjzMq73NsA/+/mE+r9J9uyWn6Q=@googlegroups.com
X-Received: by 2002:a05:6870:380a:b0:2ff:ab4b:1e6f with SMTP id 586e51a60fabf-30b679436fdmr5701174fac.30.1754311459458;
        Mon, 04 Aug 2025 05:44:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311459; cv=none;
        d=google.com; s=arc-20240605;
        b=N1zwfFkgDcinjbozFag29ElDAcMkRJzCXD5QXz5B8Ygzty80gQeoO7LKR1n8eINLPf
         se+iAkt2fYgelOQvjMcQVsteqvsLl9SNxjrfDQA0p7mxKcLXFrGQZDfDx7j+ol2Ct4VZ
         bC+XrvTvUS2XC8US3bH1YNStphX8XgMRp6RpVl6ZplLppPMkO4suWbQVRtl1W+Olna1Y
         ZOCOldAJpywbHOIeuCKxQX0jDOXOvB0ynxBi6pShstb5mk8y8NLeaDR1Pvnksx/EpFa9
         uMcVyZWXCf1A/rFaIxkCA7s4Mmkueshp8Ddp/lzKPXerOxbCZswH7/T7gWqA3o1KJ3gt
         daqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+vAkscLUbC2ztTvQppga8PLzPNKX2Zo6YASdCGH79rc=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=B/gNMvcQbQt+rPMEEFn4+YdWR1QKu7EZiRZ49fYhOmFw+PmGhbF5pfTUwqITrrJiIG
         W4ph4FxabZUUvlI9ZGn6JEPWXfpFkEfr/nCVnMHG1cE28opkK9ue+A/TjwJ2/lbJlDUS
         6IeA0rYFwRq4an6i4t8z0ERfK0ZV4Qc1C3MoJC9i+NAkLRIo9krlVbaFGHXVp4oFp0op
         9E2Q5XvbTADGRNsdDhX5OKoDAUMYgLbveiQh08fejVkut5iBJKv7XF33zMoizRBTydm+
         Zi80+cwY6Y1zZj8YSeq1cJXNlKtN9x9anAyc+VubRwWMI0DwjENKSuyfDoBpvWZra4uX
         6v3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=twziXknB;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-74186e002c8si473444a34.4.2025.08.04.05.44.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:44:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 1404A5C5F2E;
	Mon,  4 Aug 2025 12:44:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D4569C4CEE7;
	Mon,  4 Aug 2025 12:44:17 +0000 (UTC)
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
Subject: [PATCH v1 13/16] mm/hmm: properly take MMIO path
Date: Mon,  4 Aug 2025 15:42:47 +0300
Message-ID: <79cf36301cc05d6dd1c88e9c3812ac5c3f57e32b.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=twziXknB;       spf=pass
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

In case peer-to-peer transaction traverses through host bridge,
the IOMMU needs to have IOMMU_MMIO flag, together with skip of
CPU sync.

The latter was handled by provided DMA_ATTR_SKIP_CPU_SYNC flag,
but IOMMU flag was missed, due to assumption that such memory
can be treated as regular one.

Reuse newly introduced DMA attribute to properly take MMIO path.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 mm/hmm.c | 15 ++++++++-------
 1 file changed, 8 insertions(+), 7 deletions(-)

diff --git a/mm/hmm.c b/mm/hmm.c
index 015ab243f0813..6556c0e074ba8 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/79cf36301cc05d6dd1c88e9c3812ac5c3f57e32b.1754292567.git.leon%40kernel.org.
