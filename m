Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBKXNSLCQMGQESVGFPRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F91CB2CAEE
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:38:52 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3e56ff1127csf70257605ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:38:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625131; cv=pass;
        d=google.com; s=arc-20240605;
        b=kmBbL5/QL10hO4+GTmq9IhMB1/g/tvPSRnuLstH3zo0+JMUPoIBjTPLEmSiOqO1Vl5
         kCqL8R2X42RXcTzCgA160Rdhk/dsaxUdRDXT3jn1KqeRDZKGPaog9dQQNKl55/LyiaWS
         h0yOWVAAqh1wzIFOw12rgzVGWWX1kudFxZLxfOOQQ8nsjT7Nnr46f9xg49cMEF5ZBkor
         K+8xJf0e2srAc78jPPXV8NEkQ7+d2lVfOVcLDH47Yu+zjeT3PzaxGeoZwgu6VilIzQa6
         spLANYwl+J22ikjdOs6gVo7RQxv55nqDKdQeaherwBc/aK2z74Gz14nliNBDBzI0wlPB
         fNPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=dH2QmQQjkmhztCvkNSNM3RTB0FFqyq/n65ofBnOGDvA=;
        fh=7EuTN1a3KL+N3yF5WgiXxe8sCxUnV6s/36GoCdp/pYI=;
        b=DmP+RPyauh5NFlYeRB5uvMplZPFym/nr6I63DydwargCQE4U8Dvcmn9Ozdaixa4uOR
         j/cg/SgN4KfQHDDaFjTczbzPnMxwm9q0bO9EJgfBcnGvFipDrYLNZvZ8mU2Wr4qPok0K
         eHoojYrX7I81AfrOUdhpO0uq08YUON05inuDuHQNmA68OlyBx0xTVxVX01hwcJVBJ1HO
         dsH4RH+QTwr5bmCWFsNnVhFz0PjRWOpVzK5zwYGgAKmUly9wIw9YOOkJxp+nGa+jrzhF
         D5lIt6fRLZLT1IYPwqn+FZltIecr0xO/OWlh8yKNv4qWH8td+4wzGrxWcbrrWPR03C/X
         WkKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Bp6IjwCK;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625131; x=1756229931; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dH2QmQQjkmhztCvkNSNM3RTB0FFqyq/n65ofBnOGDvA=;
        b=xusplrYA0uam5pDiXn76p8+7Vk4qwI5b0wfexc8ar866SSk5ZcAkve9QojtJVcDOQ5
         34dVYoghxsvocSsvJ7pxoCst4HEgv6OozjouKqDNUeTX3MKvRupdG5guy9O7La8NGQCz
         kL99D0NvpqNuQdpwiu7btLi/Eeda/BWULa8JEgBuy6pe0klDZe8czcH4R0Pge+RF1wfy
         0+akg4uqvXvJXIUiTqWshst2MsAF50bSU71sUIEKeU3vh547MHRJD9dmzxhFf1LvreyY
         L0UBcFM7Dd7kRq+sn4ED893imiLUomJFIF320/Q/mhWx8foobqLubfTgc9IqKTegK/ZS
         Hssw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625131; x=1756229931;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dH2QmQQjkmhztCvkNSNM3RTB0FFqyq/n65ofBnOGDvA=;
        b=A8Mk1A9cB5rZa/FMCwkV0K5MKgNn4b1UcIFRWl47j4g8W0udKfH73opV3tQG1XIbYv
         ORGeyy/EODHQ+DpEbpyeCB39XBtO9wcuNSPTJZJTm6SDeUNHYAmPoAtrNrKkXTn1vXSd
         ygRoUnd4nZww9WSlKrRlTTehg1m1t2gq6KpxTvYGadfv28IrKmlAahSipqN8IPHAT8gW
         GjiNvST6e5DJKruiHxg9uR7auYzf66uqkHQJtK2kmVfimu+v1HKDVJyhPBkTpOXP24mb
         PD2ni6RpF2FrHrLilmDggdj/P3jZWFIIyjZHQMllIvrRet6J4WNw7xsLfvXBhxuJTBuS
         cpFw==
X-Forwarded-Encrypted: i=2; AJvYcCWfrPoMJ+y3ZGCRy76+RIGeSov4y9N21o0PyYPHlcdikB5CiflJEzkwi5ozNTPEceJN9Ard1A==@lfdr.de
X-Gm-Message-State: AOJu0Yy19dJCUUtWiwOHTgOuEIXakh68YdO3aXjwPhG8hF9z8FY5EHhF
	XAOf6T0AxS9ouZ1SrDpJ34HUTcqpKwAJV1B02LiBZEU9F7VKohISyR7t
X-Google-Smtp-Source: AGHT+IFaDR55unPKCk1TpTbZ6ODQC7UYWM90o/VUc0DQkLFFs4J2mQKYigpUdw6bW+4hglBYdx4AWg==
X-Received: by 2002:a05:6e02:3c82:b0:3e5:81ef:b099 with SMTP id e9e14a558f8ab-3e6765d5df2mr56912705ab.1.1755625130796;
        Tue, 19 Aug 2025 10:38:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdwXnqqCAngEh1fIve77qHBjQtyzOEktkgJswguq5H0CQ==
Received: by 2002:a05:6e02:104f:b0:3e3:e743:1e41 with SMTP id
 e9e14a558f8ab-3e56f90f47fls38897755ab.1.-pod-prod-04-us; Tue, 19 Aug 2025
 10:38:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHvgONK0IOVhRjm8836PBs37B5l1nLzkWa4mEkMHvauNj12B+D1v9sLaWqWUCbesfnWFQKVdHpLjM=@googlegroups.com
X-Received: by 2002:a05:6e02:2511:b0:3e5:82ec:d815 with SMTP id e9e14a558f8ab-3e67668025fmr53141705ab.24.1755625129865;
        Tue, 19 Aug 2025 10:38:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625129; cv=none;
        d=google.com; s=arc-20240605;
        b=ZoCnZHhfkE8yyLhuch0wfz6M/OAloHdS1dAAnLEUwwoC+FUh4rKGN2xwXMJ4+TnUbI
         K1Rvdjrw0DVpAJgemlB7PP78eIhqt18iJE69TxqeUNmsV8a6Ajzf8WBk/7XmomaTMliM
         bhab9mtzbcesm+1O2uPqOr+wonTlaJjAgvR0Spqt0asBw3HFAV6S5whzTvXAL4mAd3a1
         gpP4D/VPBuwTU/91PWYCgb8uUJEMoq59EF9KiUVOD1eZN971qkD2NfNmAj4WFetkfY3J
         +zD2HJ4UGSqdthg7dTxdQ3KgRND5DPeCaYPg/OIIR3Hk5RLT28XTK0lYLsrA0SQ+BGXk
         NaKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=D4SM6zHJ9Q6ObBfi9kz8op3wvjKvHEZA6J8C6N7vBkM=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=a6vqEcqKlrGtgD+AMmVyW4Ylh0cy4ady+hKmd0Xhr6N4TOopZUUi3x0LYG2kxgz6In
         RrXtFj4yuxBC+R2NDCvHQd7ljvslGFQZRBL7eTUHHmSC1di4Dm4TgTtX+HSYofEZ71ZV
         +xgO/sC6H1CSdewDx6zrEP8NPGZqUhUSkbotEozzYbSiSLAVqX1eQqb2HA7tS8I9RIwL
         NSVD1ZPeMG9c5/pdoHUkn7ix9E1qtIHIoc3bhCqcE76pCuAGLTCr3ewSPjhIz5XEmvM3
         I3OgHihn4sq46n3JbtERdRmyMf/i/DMVr1ZQ9g7Mkc9Qq0S+E2IUv1YTk55f/nyJozy2
         0JKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Bp6IjwCK;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e57e6655b4si5372055ab.1.2025.08.19.10.38.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:38:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 1387861430;
	Tue, 19 Aug 2025 17:38:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7B8E5C4CEF4;
	Tue, 19 Aug 2025 17:38:47 +0000 (UTC)
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
Subject: [PATCH v4 13/16] mm/hmm: properly take MMIO path
Date: Tue, 19 Aug 2025 20:36:57 +0300
Message-ID: <4b929da0b2dec4bccf489f35ee06098b437053b2.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Bp6IjwCK;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4b929da0b2dec4bccf489f35ee06098b437053b2.1755624249.git.leon%40kernel.org.
