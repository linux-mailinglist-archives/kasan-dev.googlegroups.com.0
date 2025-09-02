Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBE4I3TCQMGQELLU4HBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CCFCB407AE
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:49:57 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id 5614622812f47-437d8a8d0f4sf5608563b6e.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:49:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824595; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ftu5hb2nHFuEQMJ0GruhPTsQyMvXsjm4vO3DlA4Ty4N6sM8u+a9bSYpR9EIbXe6q1h
         +Rt5oRRPon8R29bRRk3wxUhy8Ad9WZlSQ8nDUO9t770Dx0ZD/Eq1Aj/K/9utpVK0Lyxa
         JaOF/DIHhzfHQzfoonSy6YxRjjzYL0PpcI0RFRQ+vh1/emlyZavImR6xrMU6Tu/WWhe4
         2XQih7sucFFZJ17+iGnIcK1joUF/GyOuVbQErbBOe5URQwZjwL6MXCZu5cGA9WXHBDW/
         OA0G8SffM1ZprkU4JIc6/bzW1n6kVgqkt7SVdGVfkq7QX9EWGgxANur3vqpb/HMc1ycB
         SnxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ye5JAkugwxrH93eT8aepab/y0MUZM3mcddVVBksXs5g=;
        fh=BXpMSII7QLDXexmceFMl2bu9lpTwGR3/M1t0O46Fong=;
        b=F4Op+UtQBoQVAq8akQ/kDIy6+cXtCD+JgvQAkdySECLMoM6Lwc6nE0+kyvWRAt3FQ4
         mVwCzM9ygFEdJeOKCP7htGgtGLqyUYZTM9DDal1YubkMgVDII3pe7uS/+Gv1DRgxLyRj
         QSZnjhOIGIVf3jTsB7cxVhPkrt9qC9XtOALW/DGIAV8kh1zuBAwtrFD/9YeXM0kpenLz
         8zCkugUI/qCqwoLBbaBVEtQYTjkF9LuCsQuIx3QgVXqk+lqOVHGvQWK5YJQeBAxWG5lR
         XoUOvOJi8m00onHcSJQtvh3UgkTVq0j9tImuv8RK0vpO8Vf23DQd8ryoIormpElKtgWn
         dBmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="i4LP/8sF";
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824595; x=1757429395; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ye5JAkugwxrH93eT8aepab/y0MUZM3mcddVVBksXs5g=;
        b=Jrdz0Zy0SrN5oUFM3lCpLPpoCoFTVVrqDYzFcczsx9eVRLwHnH9DMPrG1ncWmMZiBS
         bjTz5INnXWboB6yrY4twAGiG5DbCvNmMMqwgvDS6ZfzJM9Q4VNa+I3Qkaw1YU/obl/8e
         zG7TCydaJirZHYa/v2Q0eIEWk+v1pyhxSpvs6DmzCmyvjQ3637Zpnljw+ZQQAqqjoMVo
         wc5cytBii3WjzgXLuC0LQ6lzK/rlfu2J/CnPjms2If7CYAn4UjDFjpPzWO6/LLYL/q8s
         tiFQp5sIDa6OfwWNOqzLyJr2e7FuA0n4YA1Af4ukO7clCaRYN4tnao9W698JZAQidkPi
         U1aQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824595; x=1757429395;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ye5JAkugwxrH93eT8aepab/y0MUZM3mcddVVBksXs5g=;
        b=vw9O0HvwT+SzYLZS4D/iGmGLtuZb77ZZd5pzhWIiGZ6Zl0cgL5ZSQyBx7auGVt1TdS
         iU1lFtcIPPYa70W+fQxsdfMFw9Kp0rKcdTWukA3z4791X0Xe718DqyZssmeezfiNxM1+
         UrG4L3RG5hwhLd3mR9biJWNeCZCXG1REjVFrq6hHUBeFiAirbz4GDu0MNjZX5op421xn
         +tuwciY3N7Skc+LKyGcBjp1VRFGW14EFMIRU4n0mpCHvRFofMOh3jYBSJwEa63vp6B5m
         0A77djHX1/nXVwQjZcRsXyZHEJvr5tm152k+fz1cY/3eyxIoMFFbRkfarO6YhKGNMo+0
         LSSQ==
X-Forwarded-Encrypted: i=2; AJvYcCXRfEGyZGCXVuJMbXMCX5CxBOx2Ad01f9KvCj+dSwR6RGKcuJU/iMxYjY9yD1FcedmqcymMhQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyjxch3PaJBr3AxlVuU/CuGP3E9raOoFljHvsoL61WlZThtCAJ/
	Zsflak+IUvD9BYEO8VVWmghj+oXTcJPq97aDMJjmVM2voAn3FeRycOjj
X-Google-Smtp-Source: AGHT+IHoYa5s2dGcjBnBHZ81r+vj/D2b1P/W3HfBRpA47LT02yxJmKMnqWhtebUVsE4syon/r8/pbw==
X-Received: by 2002:a05:6808:1308:b0:437:def0:b91f with SMTP id 5614622812f47-437f7dcafffmr5873336b6e.43.1756824595467;
        Tue, 02 Sep 2025 07:49:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdARPUf+MfLXGbbFFPlIk9KAjY9v2ptyQAl2+V4Lwfzrw==
Received: by 2002:a05:6820:4408:b0:61e:dd7:6468 with SMTP id
 006d021491bc7-61e12473f33ls1335229eaf.0.-pod-prod-01-us; Tue, 02 Sep 2025
 07:49:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2+rIU5/37AXbds4ukIhaD1ZnTbMt/pqipDdO+lF1YsCviYo6MdvRYv97DlVggne3ldPTkszyXBus=@googlegroups.com
X-Received: by 2002:a05:6830:498b:b0:741:9e2e:863e with SMTP id 46e09a7af769-74569dd02b3mr6672668a34.13.1756824594109;
        Tue, 02 Sep 2025 07:49:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824594; cv=none;
        d=google.com; s=arc-20240605;
        b=l10PgxfFBIFcUmJhzo5051TNhnoQnetLvpoRfnMPcUKbGtRrojA6JJrSG1HufCddUr
         I1MzUBTK0tklJ1toG792YgUacQFwvgqBT3nL82wv/Ba0q58+3EDULIQkMxwimxiQbkqc
         DMpHvvHRIkTTCKH6U+7Bdtf6E5Zp6mATkL9aTBpF+Znmom6oamOlZPEgx/dY60IZWxXJ
         2bazPXM1jLaAXt/oBm7aae+Mo9wXLaDZ1tVgoDLourQFMhBWlrYogbROkXwhvl8Pw0Jl
         GbRna0eQTi1dqGzMa8njSOs1sdc7vwNN8yf3U9XTY6dHf4/xeBcDqab0dDI9nhk5ciDA
         UPNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=R5yI4ppcUgD8Bd1a/05yP97T6Kybd80cY9LOjBBrnlQ=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=CkCYyvaivNVI6Ze0BXjvs14pYH5PnbBQEQ0pK0XMSTY/PvJeW4ZDCWeUGae7dKVyKd
         q5Kp4XASST/cd9sWyOVAnlecLScQqIhf9IK0CiqT/RymUM7rsTIYl1ymVyS5t8CFt3i7
         fBuPWDn7rvhI9WLVAlHckIUEjOiadf7t3lq8Kbvlc0fbFt5fb+Z4DKoOnc9xOfy8VzA3
         0WiuTq+sfs1nAk5cNn+L78QD8SzOtmbptvjTmKM+co3LtQovuv+kqqMdTfanRN+zM93M
         odLIPp1K/BaTE9EGe7GlVTcJXC8L3kuYjlrOC+IbuqhRfBCEN7nfoiS7gLwJDhkm+WeA
         FDQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="i4LP/8sF";
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-745741df57csi324977a34.0.2025.09.02.07.49.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:49:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6DD06409E2;
	Tue,  2 Sep 2025 14:49:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7E5E9C4CEED;
	Tue,  2 Sep 2025 14:49:52 +0000 (UTC)
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
Subject: [PATCH v5 12/16] mm/hmm: migrate to physical address-based DMA mapping API
Date: Tue,  2 Sep 2025 17:48:49 +0300
Message-ID: <90d2f14352494d615d3a5d1251126c88f96a4171.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="i4LP/8sF";       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/90d2f14352494d615d3a5d1251126c88f96a4171.1756822782.git.leon%40kernel.org.
