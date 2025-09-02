Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBKEI3TCQMGQEAVDJJNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id F23E2B407B9
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:50:17 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-b4750354a05sf1184527a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:50:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824616; cv=pass;
        d=google.com; s=arc-20240605;
        b=eEZPgHS+QtVUZ9w7TAv5aITjKbJZgpIq4HvBjZ08gCK+r488LZ6Y+dpWPMOHZHjbln
         s/M+XNXh9WWAfZM9wTJovdw2j7ZIgWPzGrBIZCzMsqiRVMEzH7WhA7JxWqbuYVukz6lt
         p5aqn2U0NlznfVjJcmp9+Bxnkcgc51Ij6aQk4y7+411L2G0b9rizw10Rja+hWvdP9Td3
         H50FhXY7bMGCB+H1FyV22npv/NEQ6dxR9CFW1v7z9ocDtuUbGj0xYNvGc4UkwXloSNSR
         QayE2+3CHrbeDqbxm/j7m61GBGsjq73CHMnwPYRqhOfl7Y1aLFhAfxlvW69ccTfrLqcG
         f5xA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=hsFm1KaE6OCs3NPaEb7vCYJZeq15/C5DKv2tRxh0K7Y=;
        fh=hcJ7dLO2CuiuwEbyzRR1YSVKGOqJDMc1XHUdliAN5Cw=;
        b=VvHqNrr/O/n2xQQjEniO9PTQ06slu+m0aMRrM1FM+77vfYahuRdivTIe6iRESPPGQJ
         v52nhJQWJTKVAyo6EMSHRy5XpKaVaE1woQEIRkzWPK+feeWUjTKlpb8KZHG+nT25HpBZ
         +Rdunr5VRGojg0tu0dL4HAWZX9qPT4kcznj6Z6l2qCx0etSMjxDW16SYazs8rS8TeFUF
         +kWVgNsCnPHwkJkKCMkmWy70uuQS625hhYzMs8K53aul7IUEINQSkxYfGrl1f9621Z1t
         szY2ePnJ0tJQNQC4dPsprcHA18bkSJklZby5he0vwcKuzIM2mI7C+r4lG6Ts4j2m+B0g
         8TJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rJeu6B43;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824616; x=1757429416; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hsFm1KaE6OCs3NPaEb7vCYJZeq15/C5DKv2tRxh0K7Y=;
        b=QK/3mPMKzMZuI7jJvV/kHc7ZQ7Z/JVBkoljity51Q3a+2MeFIpmbZtZNbLx5mS+GKG
         n3wnp2dNGMxwBpkivsy4TSOq69jX/yMJGtPaqldkJj/BxxsMWMeuyb/Box8s4WQDdtS6
         TXXrMmZxtb049AAxwBUPay82gHrz1d164mH/t0fPoU2ZnpHq6WVK5cx7wns1Ne8gnqiL
         RHlJ0D8VDe5ffx52TqfAho9pvuaKtswbCrp4QpeTEnxgX4Jo+KrmHD4RcsMAh365bIsV
         pMNl8RYSLVtgsfvrnOPgkKp8SIM1DMIzsp0yZDaNQ0AVqHiDYQX8F3CiGbr7Lk7Tlgy4
         HsOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824616; x=1757429416;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hsFm1KaE6OCs3NPaEb7vCYJZeq15/C5DKv2tRxh0K7Y=;
        b=i54cBY5Dq2ARMeuXTFNMlOvOgtAKrymKKABWbtaxXNIzS87VmyPQFSdgpQ6LvMxuFc
         jpb2QzNfq00km6U+24Kv1vM1XnvU6qwPHXccvW5t5J8sMSmAZS9xHHkWQW1TxTkqpWZK
         IMMav57P0NaDffR8/gMwiCXBJbGzkkOT+esn3IFaidnsMOpAIhCZtI2u7SqzvqP8174U
         6sQK1hcBrrHRE5081rrjDrgibSeVeEVk27sdK/lyF7lJeW3wSfBX4Gq5rNWQHxMEhFKA
         iMLKpbsP46hk7q5Lc3bX4dzgPFswN+zOAYFCZ1y4iuIWraaeofxJjQ3B1R6j/qi3Ryur
         nHrg==
X-Forwarded-Encrypted: i=2; AJvYcCUcmLUNlxn8yn9IFBRyU5+Y0Q+RrlmcCo3HaTr69TWnlS4h9QWmvl+5wxskxZfIq5WG+raOfw==@lfdr.de
X-Gm-Message-State: AOJu0YxY2vTifB9HwhExm8tCwFRe3ouiLSyW+D84cfWHJ+QcywnE5rtl
	jilZTXI32heC9Ib24lq/Y92iSL7vq3xgMGpAEE7tqYxpPnnbIKly9EEJ
X-Google-Smtp-Source: AGHT+IHiHoJNjz4oQ8RCIU6ybT3GgOB/pjnWHdPPrNAh/ccHYEJMoNQSyY5MUJ3rcrIRFLwooDCg8A==
X-Received: by 2002:a05:6a20:244c:b0:240:a2fb:f8b4 with SMTP id adf61e73a8af0-243c832443fmr12030606637.1.1756824616251;
        Tue, 02 Sep 2025 07:50:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd/pw0wyU8FYqvNiWLIHQXYsXp+6xhi7oEUhzgDx7GLlA==
Received: by 2002:a05:6a00:2b9:b0:772:27f9:fd39 with SMTP id
 d2e1a72fcca58-77227fa0a1els4637024b3a.2.-pod-prod-02-us; Tue, 02 Sep 2025
 07:50:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlWy+DAmO/Kjg/6wRRx+ajD7py2S0UmNCzFI+ycwnORYUmkjP3zhEWt7qnto09D86yYiwxab+J+E8=@googlegroups.com
X-Received: by 2002:a05:6a00:37c6:b0:772:48c5:c75a with SMTP id d2e1a72fcca58-77248c5e250mr9714923b3a.13.1756824614791;
        Tue, 02 Sep 2025 07:50:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824614; cv=none;
        d=google.com; s=arc-20240605;
        b=Ys14NB7s5gRNIly+CZo1JagH7cJUpnNOexe/OBnOkGSu3BkyLfq+cZXp3KD1amWvSN
         NRpftApsQzp6auQS4Q5M8owNOHLvu6K5bCCnmI1dWS5SU1gPpnXXLmVF5EyVOrDtdAxf
         xDjhBFlhDPD/aDjziux9Guhk3ZzKb7EaoxoyJsiCcr1v8ScyfGyHITkIllJ9uPMAuGox
         9YQ7HWG2X4aljFm0X0Jo9eAQwEgfrUNKAgnB1CFe6Og3tEuWckSoH/MnD09PB1ptcske
         VNC1SDSWAUFM6sTDQ9bKd0feIgfrGs84TBb+GKusq49Aq1CLDzjeoUBlS5WYsB4cObDN
         BUjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=D4SM6zHJ9Q6ObBfi9kz8op3wvjKvHEZA6J8C6N7vBkM=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=DnCkAhYMmN9a7ZFLw03imewmEeHvca6ITZd1e29AZQ4siJlNr5IIzqtr9JF4L6aBS5
         WinLU2GZxkT/RACWQPCW75tmXCRyI+mgApPwVL1tPh7Gp879mDrNirwTq8f4uUbbuaJY
         z93/wPHwapez13oNP9v9YzHfQtmRReI6V+sYtC/N+hp6CGnzib7cOy7DvphwwfRsJVsI
         5O7jkKdZiOUVSJZhJkgeMKY31dvvNqwsTa0EvNckf9zcMNpmHuGgg0Z4Dt/UnlZSLUlh
         dKLncT7oIHZjrB6Gb5y8CsRBafh7yGlQakvQIxRQt51ZF7efqOi+mDCqeJQLizzR5rSE
         UqHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rJeu6B43;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77246129c23si370692b3a.5.2025.09.02.07.50.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:50:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id A15CE43588;
	Tue,  2 Sep 2025 14:50:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D3108C4CEED;
	Tue,  2 Sep 2025 14:50:13 +0000 (UTC)
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
Subject: [PATCH v5 13/16] mm/hmm: properly take MMIO path
Date: Tue,  2 Sep 2025 17:48:50 +0300
Message-ID: <4aac9ae9c0fe39a2e47139fae6d602f71d90bd09.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rJeu6B43;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4aac9ae9c0fe39a2e47139fae6d602f71d90bd09.1756822782.git.leon%40kernel.org.
