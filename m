Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBKPNSLCQMGQEQBEVZUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 92C44B2CAEC
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:38:51 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-30ccec4adb4sf10333509fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:38:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625130; cv=pass;
        d=google.com; s=arc-20240605;
        b=W0AUBY00iQfSS4vhAZMHKju47QX6LK6+MDd4IaMs5FHSBb7QPu9Z1wGIFnCQHAkemA
         hxRc7oIsahJb8s5Nl4Tpnq3Ums8RQHzV/0995Ldr5LL1+nRLameKBt4JC2DImhYNV+pw
         mWrrj6zHtZ49EkPNOmMRAXZkN0kgAocakWoV43/b6JIQEXZUWd1LfdqHQrv1sMU/gMVh
         O2h8f7tNodU7H2Cwm9Aer1GU30JNy+476rMcJwfawmf6pna6Q1yxXZt3gDQstc1DjEOa
         5JTj4dnF+jUZZ/C34a/GqnM9YWDasKGPODubSw+OGmLlz5MWwjHGaDjRC9QHuDoGG9c2
         sOHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=NNX7wr7LywfGTWqK2zSQPww13gC8zElxsWL0v1Nh2xU=;
        fh=fXBsMvo1D7wqVAT/9hKPXUzCxiFWaRu1A954u4AyNRE=;
        b=E4luy3vz3eqPVGzlPCZGdlTJtLn7diGI1IdVsY00v32A7x9qp3Fqmt5QoEsZIL31v2
         PkgyLuKg54+qjjbdm1goOi5Hvbuyflcd1mJ8zu/og1dR23G7KcBH2/C2IfJEWSCGmuPk
         qhUjEF4Q21YLA0XS9ha2Gdmg00WBOjMixhpkZCUlzlClDf/uKyUSg7AxCs/xYSUD8wZr
         EK37lTQHMrqR8cG0tjl14cFojWkLFSefkniu3sVsK0q7/8HB5rcfiA5JlX/ckbVUFqSk
         rnSZ73W2ctOB4uRDva3MDo/+bid33ATfUTiJD+upx23xD+A5jbMDKGjZ2qa+Fi2av80e
         17lg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ATZH+tt0;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625130; x=1756229930; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NNX7wr7LywfGTWqK2zSQPww13gC8zElxsWL0v1Nh2xU=;
        b=QcNPUNtP7/vB4lV/yLspsD7HYYB6CuAU0Fu6ZK6K5vs9bRoWi6nB+pYM6WqV0YFCOp
         MuYl6iHDjtm4yHoIly/+tfaGE0KDn4PL7fTmWDYki/l3tg5k3f2DqEBEoy+DSNL7+xIN
         W6bH77CpF1rdGmFc/kx6LaWn/hZFLl4YxQURqRA5vdlgbN7FbZVR44+yjF7hTWzpobKU
         EbBPRkqt82QPjmeUmitevLn/VdQyFLY+yHTIXaWD05FGJB0QBzMbIvLA3mKFPOIX6hA2
         13CkrAJEzrFc22fbUvpXzzXJf745U5m9zSSEXeupcIfWxkwmKtXNssfgBRoGOdqsRBnK
         l81g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625130; x=1756229930;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NNX7wr7LywfGTWqK2zSQPww13gC8zElxsWL0v1Nh2xU=;
        b=fOPMCrF052AqTV8h1+vW8dVh2tLvXqgXXd7U8TA8fYJSXxkz21SoOMBW21Pb9SpGwc
         7j9xfIUXVh4dmX80TdFSckx8XxyjLfU2QuHOfPPReW0djOjrKak2ciAVyYJEY4MtNzV/
         ImUu5NeaVtP7vsGAjszk/wEE824ZW6k6GhjJz7ypgUmdYFVyzHUV1zWmr+yPmQ0AAAk+
         Gh89LrI9xi5mQP5fNrJsD3JCepgJZ/Mpb9r3faGkSH276a5IIwJnhbmspt9HrGtnzicn
         GDD0qlebTxrS1JPXJm9KEBTNwNUpCJzlJ2uhdYD4uHp8xqKRFop15ZvKKE09pv3DVIEX
         MNuA==
X-Forwarded-Encrypted: i=2; AJvYcCUzjtQDZ6veRWNUY69ITkAafzspKjZJD9hiITrCEY+JmZygU37ZPgTyPsJauDzt1yCadZIcrw==@lfdr.de
X-Gm-Message-State: AOJu0Yz8x6eE2UHMduAC032lxfqw4B+MRxGN/lld883BEnqPo9lblJkY
	+PX7ZMAvbHMkMHaLC8n5h8bDOxaLNCg3EpWNPWEGT4uk0v8AZbk1n/BN
X-Google-Smtp-Source: AGHT+IH3rSbJO61WEJyAMm4EA+IJ4WDTUsV8h7p3a6z1BEvSm1UTWz+tDw02z+PlwPUh2st4dY3iDA==
X-Received: by 2002:a05:6870:7009:b0:2d6:2a1b:320f with SMTP id 586e51a60fabf-3110c1f4d2fmr2227618fac.11.1755625130137;
        Tue, 19 Aug 2025 10:38:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf1iSrD99mf4XdUbsHbg1cb321xzvA9t27XGs5ux6uW4A==
Received: by 2002:a05:6870:242a:b0:30c:c0b:fe9d with SMTP id
 586e51a60fabf-30cce1c793cls2914680fac.0.-pod-prod-03-us; Tue, 19 Aug 2025
 10:38:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQoDfKdAg2Yeh1WH14TMlpz1BzrX/au4CxDznGg2CRe8PtyuFe+SaIbkp6ihXoqv5ePbUoqfJFyNw=@googlegroups.com
X-Received: by 2002:a05:6808:3986:b0:433:ed9b:fcfd with SMTP id 5614622812f47-436da1ec002mr2698784b6e.19.1755625129254;
        Tue, 19 Aug 2025 10:38:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625129; cv=none;
        d=google.com; s=arc-20240605;
        b=e0bSIHo3d7cAA+oprtkYEqWsYiaSCUymilZIo/El/tFlRox+g3OwVw7Hiek2O+rnM6
         pXnZYfXKgatClRcUyYGafRbGpl8MKPvL65wqrqyB6v40Hu0sXZ7l7tN3XCbVqXas8arN
         TVvPzAL5BkMGXJ/6nqlJGgDsNOKoIHnf14o8sMv7VJf7ZMsLgGqE+NCz46EBm6aJSBgH
         G94uE7Ao6P4a/kJTouQ8vldN9XEhIVrPlIqXsxLGI3nhqzW9XMyS6fUV31KoLpmVTtmG
         KoRB0Lekc6eAg+DWRMcsHg2hKFBikJkyN08kYUBxWF7qyVrLWRCr0SDXt3xJPL7Z2kJT
         P/hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=R5yI4ppcUgD8Bd1a/05yP97T6Kybd80cY9LOjBBrnlQ=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=IuLBjBCLH6CNNtXzhr0KRneFbfEjRW+YVMOj40hgplK9a73M+DvgccIj8mQE88MyHV
         kM0bRnNV5sokBTKo4dHqRkthxBufc2yI/ZJhP8T8ByKeCCuL2FIgZrFVeJgnz1CnkLsj
         vv0GVmcOhPejQQMLeWvew2nncezYchbNJ8HwLsp/BfgtLZHkNKd8FH2KnPaqHbiH6Orj
         aoz23sgreys3Ntlr1a69WYs3qSDUZWOHQlk1nVJFF4HpQzglpk7Fg5ZjCHGMgKRJxL4P
         TxRw5yQ8T89AhBWmJ82cLjQGRuK41STe9RJjEiyDDXu4EYuvUMidSC47SKaTe8+khXX5
         zSKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ATZH+tt0;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-435ed1496d7si522501b6e.2.2025.08.19.10.38.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:38:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id A7C374552E;
	Tue, 19 Aug 2025 17:38:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9165BC4CEF1;
	Tue, 19 Aug 2025 17:38:34 +0000 (UTC)
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
Subject: [PATCH v4 12/16] mm/hmm: migrate to physical address-based DMA mapping API
Date: Tue, 19 Aug 2025 20:36:56 +0300
Message-ID: <18165db0ff83f8222bfd05c4807cda206bec02f7.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ATZH+tt0;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/18165db0ff83f8222bfd05c4807cda206bec02f7.1755624249.git.leon%40kernel.org.
