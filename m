Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBG6WYLCAMGQELZVI7ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1998CB1A1C1
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:44:14 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-23fe26e5a33sf53562085ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:44:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311452; cv=pass;
        d=google.com; s=arc-20240605;
        b=DFt6pcv3CzGJ4s8dzK5DAwk6FVbDBspyHINTcNIMf7Oa0hFBmwDX4MgCoEOcK2drPL
         tyc9Dni39OoA6BZZksRAt0IV+OsnBDpKUa1/xftayfZ2P+AgtTH9LBmkFmI48uetdb2j
         wKvn331vanOllBuAzKXZlqHkU5QbJVRNlFOFM+6F/NbHIKFDnsoBO6rhVKojkImXODDM
         +3b1W6fopEGEelvyQrNmedcWc94QwdkhkSGyootuG40EmrFxZh79hBhp7bRhRMhywgnY
         XIZA5Ux/4Z8gZ9mlfNZzxL5jqY7enjATRz2ZVDCZMP0KY6qX1X2Lo1x+8SpoChR021Q3
         geCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=PGw1e4/d2QIcbuCx08sgfzLUfmD645CTXVZgtrjQSTo=;
        fh=14ax5IEWQfccvs1bl2hsdxEeJoCzC2c9XOBa9ajkEjY=;
        b=Q4zcBSRE0Y4OBvjEXTZyITXXpKfKUO8nhx0LrmeFLGaIQew2EnJg0zi3m9dGXeiTY5
         /xkU40iFp1J5958rL2eRX8Fw7xA6pHo8+c5TzwymxXCC1/zGIr8B5M1V9F9mmMjXVk8Z
         rbK9es3w5GDEef25VcO7rV05lqEefGMmsn/iIgON1J6sBvxxDDVa2flnwdqx9CH1YRLw
         +whCywr9fjkjn/gL4hNr2/B1EmmOAoeOmz7vsk/hiE/evPM5PAkXvu4nMXOqqi2kiVXl
         h+Mq8x8AiZLBZ8bhTURfxz9sMvj1aMbjbGJ1Bie42MJfDyeYAm6Z3rzFo5rgG7TsrXde
         cZog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jbu+qcbq;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311452; x=1754916252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PGw1e4/d2QIcbuCx08sgfzLUfmD645CTXVZgtrjQSTo=;
        b=iKO84k1TdFp0dm0nFMhnZwvS1m6N2FCNOfOKq3I161EyTBMvqvPEbjFhHtOVxPDJiB
         IQCVAh/0jKUtrCMdAs1VLz/GmdWVk15XITBMF78qP/gofr5K4tS3VzGKSl6/C7i6riQV
         rAe81EB51C2aOqbPC6mWw3iN3OZ+/ssaBzmLTY5QjSVL15ncYxqn7jrwYTKTFkLLgdKm
         UU/9xYTrNfAvPOP+W4Nnm7CN49Re+uxuFVN2IRfTHwGTKaF8Yec8d7ZhwZsTl9s81GO1
         xFZdbAqKrZdRyd1zhp6lBWVH7KZmMRraX3A0Zu6CUtKRnxk6kVBWMkd3NeLP5IhUZjGE
         uaJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311452; x=1754916252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PGw1e4/d2QIcbuCx08sgfzLUfmD645CTXVZgtrjQSTo=;
        b=Sc6a0FWQCF/414WkkAk+SSL/p44u38v4x4p1qNxJ0XH9T1iOrL2Ii0AgAqo9wIvmpR
         ZkUlm7ZqnPCXIzFv7ORsoR3cJYNtf8pVfxhnLib+gJ//aro0LKsAhydFRWmnTPpVzJSS
         ufYZns4YTI3S+GbQsa3ricmDEXmNk8mkcu1tFY2YrDsTWSkNpwpHNGr8REAjxUOp3dUE
         wBZuh/niLjpSr582Z3iSMdtlLyS3RhuS9gneGPoxe21aAxg2+QFR9eGw370/6Ti0Xinx
         W1A09boikmFfcQX6CmhFk2xkas0MY6D7KXzAhcwzPRvA6rsjXc3k7gm7OYC8RnXiQvVk
         F95g==
X-Forwarded-Encrypted: i=2; AJvYcCVkmaMiCp+JIlSX3DFQVvPaFYbG1+CWi1y5zBtpti66laAocr7Fro4bCYiDfmJy0ZkHDCkV8A==@lfdr.de
X-Gm-Message-State: AOJu0YwWpYDjjEpv/8HFGJYW8r11iqf/IGJMnkPZ+oM+v1HyydaR9Nbx
	rvA31oMQ2lpNl708UWmkAxPIPoI8EUwN9tpyQF2eSYttRZbDLWOEMk5g
X-Google-Smtp-Source: AGHT+IGZOOWqdjZiI1sR/FU8f0ELNpvXZA2AvhKpuSYYk460rR71MclVdsFNHs9ixQwClvkWAxYcJA==
X-Received: by 2002:a17:903:1a67:b0:234:d679:72e9 with SMTP id d9443c01a7336-24246f68d3dmr136434425ad.12.1754311452154;
        Mon, 04 Aug 2025 05:44:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdrGFl4kAHrSV/Jglk5JjfdJ8GGF7RDsIBRYXqR7tnkjA==
Received: by 2002:a17:902:d581:b0:23f:ed15:442b with SMTP id
 d9443c01a7336-241d1eb3e9fls38010715ad.0.-pod-prod-06-us; Mon, 04 Aug 2025
 05:44:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlBwfjNF3E5ZC1HmSxfOLeZ1cN2u8rd/KICKchsnRC1mBhOMgWV0KeGuLYQCTZ2dQVmep1ZlDSX8A=@googlegroups.com
X-Received: by 2002:a17:903:22c7:b0:240:96a:b81d with SMTP id d9443c01a7336-24246f5634fmr144630995ad.5.1754311450501;
        Mon, 04 Aug 2025 05:44:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311450; cv=none;
        d=google.com; s=arc-20240605;
        b=JG0309HA+U8/cAj293a/VCIME5QRH2OnxFGHh3O2VQdj973ZHNMV6hs2nL+AAR0j1p
         PFwb4snUhsymKn60+5HSDyUm7I23dRWwfHa2Ec3AlTtw39DIfJfmcUF95pKO7x8AOJU+
         nM1EKJnL278ZF9jKQuHFZjz/QTyeAxbIRwEk0MeO/8g6+GhxwdrdQQWERNaTMkUTkJOp
         lpPefE+Hi3SitX3ihVPz8sbGjlqlY2sjnxjZk9BJs774IU8Mr0kyWdLuhw4lXFhPF3NF
         R5MWRGXKCZRFOjo/jMsiFYClqPaT/avk0mS4XNj8ehVxMaY4m0SHrLB2UMIJFWfuXytg
         PR6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZQkh9YNjcmK4oEE8V4mODzcz3fsK3O/5hMC+kUDPf80=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=I26NaR18eqwXgVD4jDrLCQ8Xx8pt+UrDlCkBRpDWKj6wuYhkgMUALIR7xofdHV9K9Q
         EMKw95aMtFS/zaD10bsLKXPSSlRLcl77sXMAlTqcLfRTlH9YtKUsZGpWqqfK3flNfWih
         eDqbqUcLixsva3JFN4TvWFn3khKBv8er/o4KDcECFtKGo1e/gFlq7/3n75JzPozvglUE
         Mj4cXUbSmfubbV+G+8wUIMjZqN7nN1V5J5gQI9huEonxZCdPOscpvP+Af6eq6bUMZ94E
         MBO19Z3Om8nZMy1lr+p57n9XJDFCuNgQ6UhlrODUQtAVy1/8GzJx2nNyO6OPMewsexpY
         zPpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jbu+qcbq;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32102a666b3si377782a91.1.2025.08.04.05.44.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:44:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id B24ACA55823;
	Mon,  4 Aug 2025 12:44:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 41354C4CEE7;
	Mon,  4 Aug 2025 12:44:08 +0000 (UTC)
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
Subject: [PATCH v1 12/16] mm/hmm: migrate to physical address-based DMA mapping API
Date: Mon,  4 Aug 2025 15:42:46 +0300
Message-ID: <6d5896c3c1eb4d481b7d49f1eb661f61353bcfdb.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jbu+qcbq;       spf=pass
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

Convert HMM DMA operations from the legacy page-based API to the new
physical address-based dma_map_phys() and dma_unmap_phys() functions.
This demonstrates the preferred approach for new code that should use
physical addresses directly rather than page+offset parameters.

The change replaces dma_map_page() and dma_unmap_page() calls with
dma_map_phys() and dma_unmap_phys() respectively, using the physical
address that was already available in the code. This eliminates the
redundant page-to-physical address conversion and aligns with the
DMA subsystem's move toward physical address-centric interfaces.

This serves as an example of how new code should be written to leverage
the more efficient physical address API, which provides cleaner interfaces
for drivers that already have access to physical addresses.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 mm/hmm.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/hmm.c b/mm/hmm.c
index d545e24949949..015ab243f0813 100644
--- a/mm/hmm.c
+++ b/mm/hmm.c
@@ -775,8 +775,8 @@ dma_addr_t hmm_dma_map_pfn(struct device *dev, struct hmm_dma_map *map,
 		if (WARN_ON_ONCE(dma_need_unmap(dev) && !dma_addrs))
 			goto error;
 
-		dma_addr = dma_map_page(dev, page, 0, map->dma_entry_size,
-					DMA_BIDIRECTIONAL);
+		dma_addr = dma_map_phys(dev, paddr, map->dma_entry_size,
+					DMA_BIDIRECTIONAL, 0);
 		if (dma_mapping_error(dev, dma_addr))
 			goto error;
 
@@ -819,8 +819,8 @@ bool hmm_dma_unmap_pfn(struct device *dev, struct hmm_dma_map *map, size_t idx)
 		dma_iova_unlink(dev, state, idx * map->dma_entry_size,
 				map->dma_entry_size, DMA_BIDIRECTIONAL, attrs);
 	} else if (dma_need_unmap(dev))
-		dma_unmap_page(dev, dma_addrs[idx], map->dma_entry_size,
-			       DMA_BIDIRECTIONAL);
+		dma_unmap_phys(dev, dma_addrs[idx], map->dma_entry_size,
+			       DMA_BIDIRECTIONAL, 0);
 
 	pfns[idx] &=
 		~(HMM_PFN_DMA_MAPPED | HMM_PFN_P2PDMA | HMM_PFN_P2PDMA_BUS);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6d5896c3c1eb4d481b7d49f1eb661f61353bcfdb.1754292567.git.leon%40kernel.org.
