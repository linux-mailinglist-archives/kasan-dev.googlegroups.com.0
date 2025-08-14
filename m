Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBEPO63CAMGQENQ5U6VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 74FD5B2620E
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:14:43 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-24458345f5dsf7895555ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:14:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166482; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vb9pyqtbegiDa/7JHGDYGGeb0YPVl/ZKPO/hgllgPH2Wh2kkA1cHhdNMRQF4GQ44GA
         swAWGQyrs44dx+DJCi+1T6C9N5tS6n3zrMnlPEA+Qjr/jL0SRBP3+GIcjOtwAUFVhLs2
         3KmmgHX5YynDVUyCuJAYjXX8/Cbt3y4cphKTkZqoanxn36x6J8G3uC+sV85HR07tpTmU
         fKEYPFPBT6wZvoo/bnw/LfGoda0t5vvpiBJQWtqt7TVFKT8Y2321FTmlmJC13NepH7Co
         RPBBjQACRavmNvWu9fJPLWhQMVAd0/i3cjHapvNMB/PKqEEH8nkAa1gnBKdE0Ty37dGw
         BfWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=u+iZ8jPEA8gRWFhzNhovcwy9o+my/yKmmf7LA4qeg/4=;
        fh=NtJ/kGe+raco4JdOa0tNZReFonl+KF8/LHODq5jum2I=;
        b=bEYVBo9Eg0TgEP1+lLGzRt8DAKVIpdmA3a3SmfP2bi4FttxkrAvgTTyYD2CQ/DPs9K
         KFjiwqq004Vs0gqlxyzRNqJPF8fclzs5qRfFy8ymu5RrcfYcDaYpQ860hTGxXEaA1kzC
         9L24CduxtvR0do664K/LL1eRohBJEu9KJoEAev+/mvi5mxIRYYcLFYzpW6h3PBEeCQIE
         XTqkY8+ioHk9My1wlTL5fmvv5fCGO/U+SzLINz+k/p35cGXPuUH9CtOIW6mPoivdWdUY
         pp/BQPgsRwa4ha1/OZxce/u+iWUapsaYbzLc1ZZ5QMDNvEuu7KEfIm+z1HADlg4O9IB7
         pbuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eWNP8pfq;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166482; x=1755771282; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=u+iZ8jPEA8gRWFhzNhovcwy9o+my/yKmmf7LA4qeg/4=;
        b=jk1deDQ70etdNDb2DGJ+L62cSeSuZ52CgDToiPdbBjEASvTJAsfWzINParM21aep9r
         qldsth2Ky97NHJdgKEzOZgVfaWsoMWu3XxfBuqNLjpprBjRoiYreoJ4MQjblM1wB83BR
         hhLSN+FYL8VNwhTTvU+7xw4/aOVlkLeASuTfsg3rCCYNKFslabHA+IZTj6mlxK03HPXj
         TyBGY29sot7V8eAO9JILx8hzCZYe+TOqjEcsTjbrr/LDtlJZi39iz0bvLKsWKx5e8XR3
         kZpVVv44gy61MzF+kmopNWXzaL79KV22b6zJ5x+3kYCTQl5t6Bk4k/b0ZD0QQibv7Sps
         SUIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166482; x=1755771282;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=u+iZ8jPEA8gRWFhzNhovcwy9o+my/yKmmf7LA4qeg/4=;
        b=g3QV96Vc1NFL8nEXaYFfF7cmjxyHJfbQfuGMGf6ZFA6V9Qro41XJuyzHB3fWTnciaI
         iddQ4HDS6tszm3j/pBYa00K5YZZ8HrBSv0qAqJrBEJp97whqKvRSWaeKzXaRYxIAhyzg
         jk80wc+eSZYO+QTs71E+ofLtgErP9PtSfyjO61W/eCZKXGG56oU603ozLkhYRdiUOqBZ
         MtP73t60yEGKWrv4Oq0N3FWrhz0B74W5dkyAOiREgmqmNnmaKxpXLw1DrRk8dyK6rFPP
         2KASzLWN9OtbeJntbvo4i/Ha09dsqHyJhUgo2TYNOyc1tNlOxsOoItC0jDbDTU7IZ7Ry
         bAAw==
X-Forwarded-Encrypted: i=2; AJvYcCUTq5aaDmlcUFyvNJX/Rk/QQxoRKYR67WKJRkDE79CfcH7hi0wvdWo01D+y0tbzJhWeiN9YYA==@lfdr.de
X-Gm-Message-State: AOJu0Yw+0/DC0z8v76VOuUYsZRvxLAG/WNIRkgtfgcAvZmOoXxXKE5F8
	TzH9c+0JuCeMtnSiK9Uiz9muGNPqUyoerpaUhiRGSU9nQW5M8WE3kx7Q
X-Google-Smtp-Source: AGHT+IGIlbo4YtWGGSjHCbe9xV3iv/Y3tBKUpsgEjXiqIOctPKmwWQzHya5H0f/MpCnwmJX4jHf8bw==
X-Received: by 2002:a17:903:186:b0:240:763d:e999 with SMTP id d9443c01a7336-2445868e40amr30618895ad.29.1755166481851;
        Thu, 14 Aug 2025 03:14:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdaPssAQDUeejtryWNKw3IyddRTgPE4ltWYBeFUKaw+ZQ==
Received: by 2002:a17:902:fc48:b0:23f:c9a2:4216 with SMTP id
 d9443c01a7336-244575ac51dls8340165ad.2.-pod-prod-04-us; Thu, 14 Aug 2025
 03:14:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUOarvtMABQXsKW3w9iPq36BiXe2UFVVihnHLtdwSaYOgvmqd4JINiESfoHG1nIomEg8pWZRsE0PU4=@googlegroups.com
X-Received: by 2002:a17:902:e5cd:b0:243:43a:fa20 with SMTP id d9443c01a7336-244585196famr42925175ad.24.1755166480473;
        Thu, 14 Aug 2025 03:14:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166480; cv=none;
        d=google.com; s=arc-20240605;
        b=Wp0Ll5Nr8QHvpkwTDlQM1B0ZSgIRLyhUlXiMLQPh/Oc4MFuq8DBmkvdz5HM7GVdliK
         3f2NXgCLV6b6xEECn2d2LG6q6PbGVPVHajjOuMgH3C7JNsEiSR2bkf+XfnJJ5X9cNUBu
         heW8LFFB/VmwlZWpXs0xW/fJxjZNwqBqolri1Gvb9o67zIkC36edqeiUOC53onv+j0gw
         /6RVnudBCTWz782s9ZljZb6DM+LCPOtIRQip8mLfL1CKYUvhWlxdGa8m/zIstktfA/Xn
         OGgOsdcn1XkOijfAkLieAXO5DoqcimIxJPvfyNtuTvIJq5BhvbgsrBsRUeQu+WOsyi9I
         ua0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=R5yI4ppcUgD8Bd1a/05yP97T6Kybd80cY9LOjBBrnlQ=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=T8LIASdZBwRNnGlexZsmjUNU92fNUo0vARivePTZZ2D39JCbuIm4ih73/3Q72+HRJ4
         JQDICDTMBsZLTkwB36wf4+aED6z3tmQV3RhuLAUhMxeeoI8wlNaWfzq9BtSAgGkq+D/Y
         y4BeIOU2sdzDPPSEoxsLAtNde7Mq4OqoTm8W/iZQBPP0KCkOlCF4HynETmrbhpTjDCJY
         bBqbrJ8bhFRVUfcRqFBAbrJoyUZZ00nwJmOualuwEEmRNH2APxaXL1aMJZx8JjH4JsHT
         a9vKmHuiVEve3RFMGURyoC+3/h/s6SskEeGexGAfplcnNxtKGZRZeKCrU2qN7p0RqO/N
         W3OA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eWNP8pfq;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241cec02f6csi7066375ad.2.2025.08.14.03.14.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:14:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 4E066445B7;
	Thu, 14 Aug 2025 10:14:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 27028C4CEED;
	Thu, 14 Aug 2025 10:14:39 +0000 (UTC)
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
Subject: [PATCH v2 12/16] mm/hmm: migrate to physical address-based DMA mapping API
Date: Thu, 14 Aug 2025 13:13:30 +0300
Message-ID: <259668e7a332148edf8738b7b4637c2b264f51ea.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eWNP8pfq;       spf=pass
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

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 mm/hmm.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/hmm.c b/mm/hmm.c
index d545e2494994..015ab243f081 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/259668e7a332148edf8738b7b4637c2b264f51ea.1755153054.git.leon%40kernel.org.
