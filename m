Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBI6XQDDAMGQET3LVLYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id DE617B4FCE7
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:29:08 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4b47b4d296esf139877161cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:29:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424548; cv=pass;
        d=google.com; s=arc-20240605;
        b=fEp/RNrIQ47/45/Djpz8MFenq4dckEfMHwCXoQ0E1nNCKpFtNdQfKMVV+J6bxJNIuy
         2oB2GbTj7VOXALgwwikAjUu1DlealwAeAJ2bpRGIjiaTrc+PS5qbHUDUwV8jgszY57CZ
         YKS5oVQzHGzaldLrj3hOaqUU3/rZqxBMHOWVdy80ualvtjTpNdx7pWlll7zKN56RK5KJ
         rKpg5zKKSLnhNiofW0jqbahPs0XcRweQ5ggDV+8sPNEBoKNwXRup2yc9bU/fldJyGQQx
         9qFWfHfKvFkjTAZLfW6AGyb8NGs61qgQe6q67s2IzKFoKK10d1SItSPSYk4IAh+q40/v
         xMnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=lRIHbUE/jdnzlfE2ykaWvwBbcKhAhjNR88p2/dOFaT4=;
        fh=DwDjHqN7A3SbJHTG8ZGLWUK7Z7QESn3PIlAtlwBCVuY=;
        b=HsOYcQPKShC1YDDi/PIznXljZKwPIPdwwkuLqH30dG8lcaCD+vn3t0MM0cPQqRMg5O
         7i5zuxvfElrH21UHQAOUphAlxw3cSIyVxnQ8J1Bl1G96QqlXq7E2J65NslaM3sfGWwUr
         q/4t0SG00aV+r5/kr+7MBIf2PTGC85gtCt43ZdgDZTciQSuNsc02CSxPcMj/v3BR7Its
         +bIEu6cUJZCI00AGjFO5SGfj60FjUJjXusX89wQ+FVStaetnMy6E9X7wbEeLy2+IWnEn
         225TmkjC75J95MoP+2me281pIyPvTuPRzt5nc4nlgvxmzVenElZM8D5oGor3a0pyEsDz
         eplw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tnTViotB;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424548; x=1758029348; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=lRIHbUE/jdnzlfE2ykaWvwBbcKhAhjNR88p2/dOFaT4=;
        b=HEvy9iyu3zavFVvnYkSNKenovsUo0wBTArHjPrWGOCZzBgyfnUi+fgi089vrHTknbp
         iw63s2xXrue3d1Z7VpcUMo/g6DnWcEY8eWoBYHrrSO/UjMHUJUuico67Vnv4xedwfdva
         fT2wnOOmgmopL1H6pIRCnx1vQJOyc18jRh6Gll1E0SG2yCt9omkfda1eHmU1TcKUyFPj
         Qgbp2EI3799EXq+AMYKOZ7rMU8CPlQ68lXXPRF1dk3fIm5/PabFAUsrFTMMq4PVtGvGb
         nkIC/G9qb3Hg9mPdVOxP18/L/yO70yuPTXY95zH9ff9kqsF6x6F92lGGM01XvzHD34fY
         LTpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424548; x=1758029348;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lRIHbUE/jdnzlfE2ykaWvwBbcKhAhjNR88p2/dOFaT4=;
        b=OIZtnotVdNwWJQl2k0fPb4sqnOXIBf6/JXjB/nf4sF/WNw9wor19jaGROKBCLszh0o
         5N9kB9XLWxq/RJ45+NqOeOcvIU3UFbUNSzOmhtYtJ+tfmtoh11uRDxR5qNiWXIlAQVOv
         ugxvNa8ZehY84WMmVaN67QQv1oDuX7ovV+HkZov3tLF7XD1LzwrYJvCJ3Eodq+tn4w2I
         4OInwoDmvyy/9HfZqo1JnQxIWKDretX+Ip9xpCaLKYh4IIHvPrTyOIPC2eOo6Uq+1fLr
         v51UM5kh8+SEW+EYEk4KRgOkfl/UgT4Q5d+KoR5pc+HdYH1C2rJmrG4F//GL3m9UUK8P
         yShg==
X-Forwarded-Encrypted: i=2; AJvYcCU6zOMVm6W8CTDStR7Eb8Lmpjqn4OGiiW7iBTjFFe79lA5CBgDfOvHFlt49Wm40O5nGLV9x9g==@lfdr.de
X-Gm-Message-State: AOJu0YwXpBH8x9kvtznVo9h6sAwJ59zD9FZJ8jLFimLc3y9/GqJF6Xb7
	BGnTAaW47ZvEisB/VA2WqdFJMIXseor2RRN40J26fecmD1c+WNwTe/h+
X-Google-Smtp-Source: AGHT+IGqmEgeUqXj3tPR4uDBZjH4yk/ADaCVYtOmq6bVsdohL5LhVLdLYcCb9lq4CVnFEZ6/Nqae2Q==
X-Received: by 2002:a05:622a:5e0d:b0:4b5:fa2e:380f with SMTP id d75a77b69052e-4b5fa2e3ef6mr87272921cf.27.1757424547666;
        Tue, 09 Sep 2025 06:29:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc02k6axHN+3RNZ3wMWyMSDSDkGBnymHJP74Uc5GkZ07Q==
Received: by 2002:ac8:7f91:0:b0:4b2:deda:ce94 with SMTP id d75a77b69052e-4b5ea98fbfbls79663841cf.2.-pod-prod-02-us;
 Tue, 09 Sep 2025 06:29:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXAXk3B/DGhsyelBuHh6Np2+CvmiOA3ppd5yzhqQRc/gC3DHeDnzWM88a5GsPSU28boEJEGTxOzgPQ=@googlegroups.com
X-Received: by 2002:a05:6102:3911:b0:4fb:de9e:6d87 with SMTP id ada2fe7eead31-53d1c3d77d6mr4222020137.11.1757424546380;
        Tue, 09 Sep 2025 06:29:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424546; cv=none;
        d=google.com; s=arc-20240605;
        b=RB6p0gm3jn7qMr6ipXdhon+7Wo5+UdHjvdwq17OJx4KyW5SFdDLv/2AoLCSynuHEeY
         CTSmjyrxneIIJ5CQIYmcIR50XroyRMBlQ3VOKy/49gxXPHPxIYDfhqVsdh1b7KqWMxwZ
         7sjqeSF11VR1/mZzyCuW6cLKqLNE5fZ1lXT+1vvUpKdD9VIENJRThRujib6lnqc6TzsR
         SAY2RFiK+1txkiHfategXAJzpdTLQOqieFbXgYIksu7hJoauUA4KGXc/4uGdZfjbO7hB
         bfn1l97XZrZ1Q71EJHVNSthoO1YPfdL5rm+tkn+7ggWYtTNIG8eAyvhzrKqMSNkN1oBY
         vxuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hT6tMxxj7QGpFRMwj1+ZfG20o1qByFSHIC0k6CdAwac=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=KfVZZtF+Wgk4Q8kSv2JcCXBAmnAH14kXC0fx228ZJ1jHbCpxMQGFS5sSGiy48MXdKD
         Ch1dXj48c6suQl5oVXdQVXEcreJO87q5EcnN/yggYr6GwI2JqvBDCai+xcCNE1eRc/Hn
         h75LBsKZkosLQRUqkQkT1Bgshj0DpSZyiRyoKymfwUPdZy6EMdAGkUvSITQBI1EqH+FB
         l3mCEfUOZ39AJCBoYCkCYGsaVRqn5T0GtJ2uJKY2QzB1QzaDR4Yq8JThS552H/Od6pXJ
         Td03+rSGiDI8fdIBnlOErUZrjH8jvxznQCg5hSgxZHxkMn+PAOIh8t/rRL8AlJpGSSlw
         +08Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tnTViotB;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-52aef99551bsi437333137.2.2025.09.09.06.29.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:29:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id D79DA601AB;
	Tue,  9 Sep 2025 13:29:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EE671C4CEF4;
	Tue,  9 Sep 2025 13:29:04 +0000 (UTC)
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
Subject: [PATCH v6 13/16] mm/hmm: properly take MMIO path
Date: Tue,  9 Sep 2025 16:27:41 +0300
Message-ID: <998251caf3f9d1a3f6f8205f1f494c707fb4d8fa.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tnTViotB;       spf=pass
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
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/998251caf3f9d1a3f6f8205f1f494c707fb4d8fa.1757423202.git.leonro%40nvidia.com.
