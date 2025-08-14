Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBA6G7DCAMGQEPG6WPCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 17F1DB26E1E
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:55:18 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-88432e1eaa5sf246592539f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:55:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194116; cv=pass;
        d=google.com; s=arc-20240605;
        b=TlPzszi07fvOzMWbhS6hRugabNyBZEL5KLPgms4NVJQMPYtfGSTXHCThGBpeD7hXLS
         TzQ4PlGCQAfaBCewsmNXvCejeBMquVUStaTHbaYO/AXUK+dwlHA3Y+iF3q28mrS7IdgS
         Da95d74gYnQo9qh78eWoWmLmanYv9F9Bf9lZKwvxbYvcNRzGWNbJnlPzNcOUrmRwIIPI
         xxQ3SWutYYOpHv4Y7dvz0oLtmtHQMeD7PP/h2YLNlWaO2XjrxxG0vHvH6X2gEl8pVOKF
         xEhDrM3sW3spEWDza+UwT/+shuCdbpxLOmxxVtZP0HdJ/Gks+rv445I7MSNlIqmiBHf3
         5/WQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z3RgKZsRKgKLTruLbS5LwGhH03E9XQDQJVpzSXzKnUc=;
        fh=bpWmBc++zbvO8LQ6xn+/4FJ4aLNSrbMvg3KX808eEHg=;
        b=P5NOrHTEQSvygQ2QVL/2wQ4tvg3jjozEPPu1PhASPUrnNx88AEtkxOA/p0f1a55VNt
         nkQEkMmH1Qn18C/X0m1lP/nh2Vhjsh41qEq5IK2s3VJuoWnW5mgMJpCA1nqJXHSRUh0t
         K4uQt8dQAAumbANODtH2nhMyJgyfavmxtOHL2OeRHY1wrLT9u3r897OhbpjfNV5OH5pl
         rJULn9roISpMM83rAwDCuiE5U3GaKSuMULeotxiExmu6VZegaJ3XR5c+tGHGSqBNENL4
         MpCKj8wbvEDqneDqUBZnYr2r9HxjiJPzKvLai4FNR0w66evMOTpFlbwfQTje59ZOqqUt
         Zf8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EroDnati;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194116; x=1755798916; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Z3RgKZsRKgKLTruLbS5LwGhH03E9XQDQJVpzSXzKnUc=;
        b=hcMweLrSqyhftBUhR3/fFETOnL8Z2TkEb4AIwj7WWlKTpFNWoLT6Ubg1xl1L4AupYF
         AtE/vvYSkV13A4b/Fk7Q+/4aeuxPv7x/64+UhRSvjUL0A5xZ5hU/aGxgo6rnf9kh4Plj
         ubOlplJkLYzxcWdfzUhIhniWjiMRXJQvTYH0ItId5zztRpFmpve8Q8dxOe1UALr4RxEq
         xKlCaPjViaRXKXmYKiwky5hmo1Y0wyciuxssNveyXU5lTe+RLpccjVXjUZprcWAHZsqf
         zYXTMESvjsNkdX9bCuviMfLWzYjsS2flHl1iuBJ3IX1nd9TPs5OBVpuEkGQU7WcVupCS
         7JnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194116; x=1755798916;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z3RgKZsRKgKLTruLbS5LwGhH03E9XQDQJVpzSXzKnUc=;
        b=d7MbiML6PUdtAxMmrf6IE9UKu4fqiEe4eTBSspzEY+goTKlwrkhG2lEZy37yCaZqis
         CQR39JGBLQxqExAKrlmujW0dnvv+egNN0xyo6wqUCas1WNaP+wIIZsHicUFaKOarjV7m
         kbYP68QPLbb3dakKJTFGcuwNn1h4z2NT7FyowI6d9Vd8iqC5mbaDs8gbUpQx5oIlru/x
         Jpn+tv4mUBHDj/JxfGgQF7V7PfL/dBA3AET/0zUoKvU+DyZpkv6TlpNBEuMGry/CIZLQ
         MqdRX1QCYT38qsUqToN/6qeaTAINaC/bGv9Ai69hk2LBNknJ2OdA5ZsWYFDaQ8Pw7XTJ
         7cCg==
X-Forwarded-Encrypted: i=2; AJvYcCWgqLewTxOSvSCVOUuH3bZrVUkGtSeDS1E4PcG2xKKlvTO3e3Kyo17NRs0Hiwv/vAh2DUJoMg==@lfdr.de
X-Gm-Message-State: AOJu0YzlqbjPFR3naNcF3tnBSHAYGBULe7Do6IHSXneQb7eawJFQn4Aa
	EVUJSTEMQO2o6pyBzFt22r82v+QczFD9HQbBaGzMxBKAcXz6CALaH6Wn
X-Google-Smtp-Source: AGHT+IG+oxXesLLJEGWBABq3S3vvrzmRlqaRMSAj+mPtkDRk1h/zorftFkSUqSNkr9nVFU/8qry22A==
X-Received: by 2002:a05:6e02:1fc9:b0:3e5:58ba:d9ca with SMTP id e9e14a558f8ab-3e57076e5d2mr85929255ab.3.1755194116033;
        Thu, 14 Aug 2025 10:55:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf2SLXxrk7U8YwuTjyrNxISO49N0ba6BO83H91ek58YWA==
Received: by 2002:a05:6e02:1a0a:b0:3df:1573:75d5 with SMTP id
 e9e14a558f8ab-3e56fb53fecls11948855ab.2.-pod-prod-02-us; Thu, 14 Aug 2025
 10:55:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWXEx12PT9bPtcXdXMa+vyOu68WnS8v5TCjkDeMBVJZDIhvpaPPO3yFCwqkMiaZCNDrFNs9fG54TC8=@googlegroups.com
X-Received: by 2002:a05:6602:15cf:b0:881:8d1f:1a7c with SMTP id ca18e2360f4ac-884339cc3famr741628739f.12.1755194114760;
        Thu, 14 Aug 2025 10:55:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194114; cv=none;
        d=google.com; s=arc-20240605;
        b=SxQ/6ZbdiE6ZBKufytLNIp5mmd1/Ibckmhre5+nEzvNU2ShUR0fb/LhLJoFAADsFIB
         RYqLozauF8L/UWAAElRX9TYUgkDz/5UPfE2UMOYwdJ0kgvy7pNa4AgeAP0j4t/obadKT
         ywLu9WpTyt2lzGFmHWNQKdQuDdXQ8m9rTECLLwktaV/RFl4+UYqK/phXqi6n2xEaozQ7
         TsfvCzVdqtye0oLgngi5fBb7YyOJznJbUoPmdL1oFwa8v6b9JF9q2vprduAXcIJYLZSc
         t/g19y7bzw8kApA+qGCipg9Kjv00Gjx+2lSv9GPIyGtDtKAEsZDF0SHV6FVABVUUcpe4
         xpKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=D4SM6zHJ9Q6ObBfi9kz8op3wvjKvHEZA6J8C6N7vBkM=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=hThFHUakJIeVMXSWA9HxNWmALbakT+rvvBoEYlNGIfYm0v26rrcwyWQobC97dP116O
         IUVDLJ6eM4Z6hJd3VqtcKzrY9TYd77MpmCddi+Uarum1HFUtPyRzlo+aA1fG036TSbel
         aQAKOXN5Ih+mg8KBHykoU7i9Tq2RZSNROnRKOLMLHq8tbC3RS6m9FQPaL+tXwiiV0Rja
         9u3ZYInFp0rIcJFvJQVdOK4KFzIdjBrU9paEdC3DSg1IqI6E0cq9rvyujgvfv8AOkWbH
         LzpQ9ZDe3LOmCExkVfsR2hKgSYQ86EOHc7gNyjgEwDvPejtk6U4kguriSZbysCZ9t+vm
         X6mQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EroDnati;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-883f18eccc3si75338839f.1.2025.08.14.10.55.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:55:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 2FF73A56B3C;
	Thu, 14 Aug 2025 17:55:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 062CDC4CEED;
	Thu, 14 Aug 2025 17:55:13 +0000 (UTC)
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
Subject: [PATCH v3 13/16] mm/hmm: properly take MMIO path
Date: Thu, 14 Aug 2025 20:54:04 +0300
Message-ID: <44e4937b3d906a77a6b905946f8a74b49659b0c7.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=EroDnati;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/44e4937b3d906a77a6b905946f8a74b49659b0c7.1755193625.git.leon%40kernel.org.
