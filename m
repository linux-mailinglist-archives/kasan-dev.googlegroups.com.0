Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB5OF7DCAMGQEXUJND5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 68042B26E17
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:55:17 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-32326e21dd6sf2252761a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:55:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194102; cv=pass;
        d=google.com; s=arc-20240605;
        b=UqPikpJFoFnIDfjvrL0RL7fT8iODZQOB0tKreXlpEj1Pmf3cpVsfLBEnDHDeyTGGC5
         pNyvL6+257mBIFTxRYM01JAINJR21VtEMKfYVLI5l+yinPwu36/q0G43+2Umb0W3eZe1
         GBtu6w/Uu9uIvxjD41BQTzUlyhDDp/qHNbFu5/JJQ/ggVAoexlUTSE9CTGjQgOZ+VOL+
         uR5AExjDdQ8IXcH01SzeWTykThmKjb+9BQpItzcYfQCIxOU6o7rcLJBpcbClir6Okmzp
         3OwKX15I7urACAE3mJDFY6mFreKLrlPkbS7wT3egAWQjw+HYYn2B/lNNvf8cXByZRs2R
         2slg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=TBcxU8mIjF22SOcDEvUAvE2MUEAAAX9FUBsBt0ccqo0=;
        fh=kk7HhS27jbCXFALgG3zWbkuZqsGcUsjGJx+8xUjykfU=;
        b=MmQbbWWElvRXgNZgbekLEnp9yRPz/WbtMSTrhFc9lvqWn+QBepxUiMzizCCXvEjBro
         sKDGFlul+CIl2LGxB3lQtlktgqY/juoGYFAsvk1zmJ3nsjnDMSd+SbX88TMX+CuJAY/D
         CFZUn0e2s3VdAnhIoygEbw+ivN2O1PvesITL6XwVbIMKAhUqJJ5e+JcCL6b0F5Rj6Z8R
         VBOS2lRUTeVRT2rXwDyIA4D8FdpSGKrKJDaCADSVNU6eiXdqhLEipB0k1Oq3FYIJRAjs
         lVZF4gpb+LkXqzGkWuLGkNouRGbQDO4IKP+zzZ/CkjLpX/CH9zpKc5NsvLxxJ/9HoXuo
         uatA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CXSCeVE+;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194102; x=1755798902; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=TBcxU8mIjF22SOcDEvUAvE2MUEAAAX9FUBsBt0ccqo0=;
        b=FdWay2+5yRcJfF/5W6mzivDyGIRBgmn22DiMkic6bXg6COr56J4MHVbxhLt4DfujoY
         4ObPdWExqD5xMUMyE/mGvdtoVClEEowhW205DeH30OaU3VGW7MUtRG+OA1yk4OHTtW+u
         SL44YE8MXT5hKHzWcxDaPAt1/QlZJgc0JU5XdHgz3wizRpfauar1lN60HJZz4jXGojVi
         0N39OqHxR2+mjKzXtwLZosEaWustQUhXAY9ymgjcBtg/ZfkkFpqKN6maf8tJA0fN2oHZ
         Em8obwE6sClDn4I60IgoKQdg9SEq23QzTMhYx8N84+u3aR1ab+SfckWw5tGS0Ofnfge8
         B2HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194102; x=1755798902;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TBcxU8mIjF22SOcDEvUAvE2MUEAAAX9FUBsBt0ccqo0=;
        b=ja9I8mMNx+tHN5soqPHMWNWuY1Ow4gDHUsBbwZT6GUQ4uT6RTp9zhGCA6x71YA34ow
         Tp3nmpH4TDsa1OuHQaYeAeZK7fFWAMTQ5ox4bjXvlVq+5AhGYs4Jrht/SvuUgnPUIxEj
         8TbMqsSsOsT9sRzeWRZVvd3nWocNyQFs3Yw0ryJVP5usloJAkvQXubyw9l+DGeSLsz4i
         VqhQ1CSKBqHkeir931ZBFGB5lRbwbqWoj7JaYDYUcXW9OZVJMr3/DBoQP6qP+MaDLwOM
         kUJB7UUaNC8nA1Ctev7RR75gS8qM0u5lZLIO7V4hzHGJMVwMyN5dGX9U7CVPrnLxmcPz
         ZEpA==
X-Forwarded-Encrypted: i=2; AJvYcCXqiM6Zu9nAeR5F5G5R/B7su81btily3FRp0hek1wTyLgtAJtwlpWgUq2RSY2ju9JgFB5IWMw==@lfdr.de
X-Gm-Message-State: AOJu0YxExRrHlEG2CaZsNORioK6fDnLKoe/dz9HWsbdqF1fRm3ZptDpo
	oiV+5Lcnyc7H/UutiJiTdZ5B9ftfDKQ5SsLjQK7ijsUc3uYxJRnGFdNF
X-Google-Smtp-Source: AGHT+IFJ3sF03g8AHuWP0V0sdz5aTNl7vzApOpulQBQfrKRL4XW4Iog7W5nbq83yUh8naK4eojKDrg==
X-Received: by 2002:a17:90b:1810:b0:321:a2cf:9da9 with SMTP id 98e67ed59e1d1-32327b3df55mr5747403a91.15.1755194102157;
        Thu, 14 Aug 2025 10:55:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcBGMMfxETv8rlva8PU+KVqT1a5Nnm2C4SWdC+mU9BZpA==
Received: by 2002:a17:90a:d57:b0:31e:d9ef:bdc5 with SMTP id
 98e67ed59e1d1-3232668f39dls921891a91.2.-pod-prod-08-us; Thu, 14 Aug 2025
 10:55:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWyNuF7nZ4cnhH0vpK8HeEVKXzvi6gNajqJ5+BLBYih5Rh4y3bS9ulkSNAiCSpEMyedQpYmCcmU+nA=@googlegroups.com
X-Received: by 2002:a05:6a20:4329:b0:238:351a:6442 with SMTP id adf61e73a8af0-240bd2dded3mr6737400637.45.1755194100057;
        Thu, 14 Aug 2025 10:55:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194100; cv=none;
        d=google.com; s=arc-20240605;
        b=RTfs12wVQIXDHoMvGTElOTj8TgQ/LTyKetf+lk9wBuRBS5CdGS0U2LHjf7nvQ3GfPU
         NTHDhXl+dQLNMUnZJqMKCgDfne70hLs+sh1Xk23yg9lL00ua/d2gXublMNa+4EG+sIM0
         RsIMLrqfxwuDsrEA9XsHVLtNipPFhTan4AP64xenT878ew2CYT+Q4abED2lfjKBishVo
         uJrR28kAYTH4Ur3q37jxshQ/a3NrOqy5gR7RWlswNuv4mAkHs9CA32DqPJ7eNR+XuFOa
         iHghld7E3+J7oiM1aJbvZczQspy7hgHVtGL22eQV7DM4d3owKKydVuLwfgsZqa3KVUk/
         eGGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=R5yI4ppcUgD8Bd1a/05yP97T6Kybd80cY9LOjBBrnlQ=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=fHBAR++Hh3uqDPeceg/Yih+9qLjzgeIw2I8XAI4ioj8QNohKTc/DyHAECxMxDvXo1u
         y/W6NhwDEOCI2pRuxfxALihobRVIBjIZhxJAncUt1g+vxZHDskW0Ikkvh1s1eC2/TjD1
         q+z8QzHQoy7lnIiLXr3cHvysvBZJ4LEyX3G6zXacClrL1+D7vVNl+cbupYfF3gZf+kjS
         d5Nm8ZKLGSoZD8ih6td8wVCNJPl5mFS2cyIlTEZ6DfEEaCGIjFEpiIyvSXqDcKSGGDxo
         +SrF7dz9Slt5Xw8iBh5dzuVGOoO7JMWP96OUpqWpIHV9T0MCaThK1+vXEOJm7zqU6rO+
         vKbw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CXSCeVE+;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b42a1fb15cfsi618958a12.2.2025.08.14.10.54.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:55:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 5CAFA5C723B;
	Thu, 14 Aug 2025 17:54:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D761DC4CEED;
	Thu, 14 Aug 2025 17:54:57 +0000 (UTC)
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
Subject: [PATCH v3 12/16] mm/hmm: migrate to physical address-based DMA mapping API
Date: Thu, 14 Aug 2025 20:54:03 +0300
Message-ID: <dfa67811bf82079e888fe9cb3fabbbc5a05776b4.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CXSCeVE+;       spf=pass
 (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dfa67811bf82079e888fe9cb3fabbbc5a05776b4.1755193625.git.leon%40kernel.org.
