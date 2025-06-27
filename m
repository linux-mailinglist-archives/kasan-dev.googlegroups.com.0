Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBG457PBAMGQEOI5CAIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 0776AAEBDFC
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 19:02:24 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3ddb4dcebfasf65517155ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 10:02:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751043740; cv=pass;
        d=google.com; s=arc-20240605;
        b=fTDCHQF9hJE89dAVVrPlT/MRmaYrWRenGkardHpd6WkYCj5W40ya2dPjtWvDvLt5s+
         4Ca4fI6dOH9MMbuBFzPtXUqU+ICUSYPm/8ZYff3Fd4DbweLdBAr1QjmR/R0wK8L0R+LB
         JhXpuLZKLd3UE6sBZt/ksIAn0aPj/GPZAJQTn6/XSMRWwqYkZS0lEKA4hdfXj8cQOfug
         qLP3UpVkadXarNz7Na3+zzT8zNyJA2ee9z6d0/S9c3rdSsiEprGkX+voxFGV6Xy14m//
         9pOWvymvb9ycOXCnKHyNAz0UlT5DzO7QHWqaOJolJYprYBy7LE8jN1815LkaAofa+kl3
         d+yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8PoKtYUt/SI+NspIRxrRnLdabgnClCSmHeqhw7kdFNo=;
        fh=b5U5UVA+yaDoNntx2Gbvaxx7GftVHmjVFwBm2QcbuWQ=;
        b=OYKPgH6g4i9PXCtM8CUKQBU3e/iSqeoJVpgnDTq3hQ0AWeK0+BUoArrBmL/PKyrBlX
         QBN04DNbvILF78Fx46lsGnK5XuZWA/UsmmomQ12nxhKBCzQL5d3cBIuHvn97fmH3+c1H
         rh/cGLWjesXeFHWrgI+JRhCuGCmn/pZnVNRmf1FlBuB/eIuq7xi1nM085da1tdVOd7rq
         u/9eH2Z19P5z/w7ptNZ4yGCYFSkdaRYFcGo9LydPgL2RFtZ6NrLmIxXJ0LgoBRQhi+tm
         lvXNO6DymZBKBlvpIX0G85qd2iWBOLnhExG019X/urJm7EblJP6Fk7XRAIrbrs41buAL
         JtnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tvSgedwL;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751043740; x=1751648540; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8PoKtYUt/SI+NspIRxrRnLdabgnClCSmHeqhw7kdFNo=;
        b=nFYrK/GpHb0Ne65/wUBl0MQIxAufqp8VQgxPWNBZD5aozwpJ0FSguhzj2VQmNZ4DJ6
         zsPzytDCsq35b5jco5/cfwQ4N/qi+5RoWT9Z+FITXLU5lklN6XmntX2h1jFz/PNxkFHR
         C6sA2ZvWgZf1M/0dJBVkXZL2ZSMdHenAbg2mcyImlVsensTC1CWplXgPdwlns4uNEQP1
         bqgqp9FTvIVNx+TDJZIRGfQlm94Ad1Z5DbUNs6MP+UKp8mXURWp40XQE5xdbQ++mF7ht
         l8/ODOTgDf0ZKHrqzBb11tGLinKIT5t/D6Pzj2LTirz3LqPWp6qYRtSJTKAcgZw8ZG1f
         5QeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751043740; x=1751648540;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8PoKtYUt/SI+NspIRxrRnLdabgnClCSmHeqhw7kdFNo=;
        b=E8PmHb6w5wlNsne/JH0tZlGBUpQIUX3VyvooxJI3QegWhDiiSL+RWwPxBvrm3Xka7Z
         862ncJ+6IkUq/8r8Uh+tWr7VgpcO8MG7/7F+YkJIKAY7NL7N/zOXlB1lDE4WIkFzc3gI
         0s3w0u+zssEMfAIijGp+lod5kiFR9Jp6KME3tkiIVzAd1hTpg628ofhRYkzJYrhWzD/b
         h+n0ZzbJKK80mf7l9m4OUnmPgw4RgvSqGBcj/sx+Yit5mO8C8NxpJBWJmeWncFSdAIpb
         UGPAgJij9bG7UxVBdwDLp0kYGS0nJSuBac1930aPfexbtb1CkwBY5Nj3fHCXvuYRw04U
         1Srg==
X-Forwarded-Encrypted: i=2; AJvYcCUPF80KCyQAL5Cf2m0w4puIV7shYgGeq84+LK05k8JtluYDxVDhChyQdR194in5nGNhhZB6Lw==@lfdr.de
X-Gm-Message-State: AOJu0YxMSaEZeYPJXXzIj01wuS7+AaCxDmfkOWMssgm/DePxpR4UJsQM
	VuugM+rtURBzq+jaS9Mnm0midB5SQg1VWWYAn7menVbbBWpuWDW2RnMT
X-Google-Smtp-Source: AGHT+IEKPD+woPZ8Nv0OEMxAmxphOvfnna46eMJwy+6xbJHeGEtoMy5Tuk1dycNPkDXS7KQa7wqwqw==
X-Received: by 2002:a05:6e02:219c:b0:3dd:cdea:8f85 with SMTP id e9e14a558f8ab-3df4acc8010mr57003535ab.20.1751043740081;
        Fri, 27 Jun 2025 10:02:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc9hytuIM2kKVSnaRmCPLMfuCiheAC0cVHRB6MOZCo9gw==
Received: by 2002:a05:6e02:4612:b0:3dd:bc0c:3739 with SMTP id
 e9e14a558f8ab-3df3de0e747ls21813475ab.1.-pod-prod-01-us; Fri, 27 Jun 2025
 10:02:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVyRNnEHpj+AtqU1XAmXJ2CdCKKtOMQuUr6lx22U2D89n0hzN1PxrYWhhDiBzCP0tw/kV8DX3GGBNc=@googlegroups.com
X-Received: by 2002:a05:6e02:194d:b0:3df:3208:968e with SMTP id e9e14a558f8ab-3df4aba4dfcmr47810555ab.14.1751043738781;
        Fri, 27 Jun 2025 10:02:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751043738; cv=none;
        d=google.com; s=arc-20240605;
        b=Q7ZiWKyB8nwwZw9QzXFYn803IFiS5cnHbBUioid+8aJEfujk2UGH2aKwUM8MtZkTqY
         slkpzuzu4UgklHnZyon84XjZv84MLXMRTWe0NhDFDlzWIdBVRn5N0CTh0OlFpSWIvwHp
         ub6UZgnNvB4sWS5M2mARIU6740DUOnRZPo4QkLuZw/nF6o+J9ycXgyGd6qY/jQ1DJLPp
         m+lbpugU7rbw+VxB5Cyxjna4h7JwOlfGb8XbSPgru6cVJtQgPYxzfYIi6zoeMvNaAG26
         HjIrogGyh+2Jrzc/XCPINnSjcWlON96lPWa5eSQa+k0GibdU1amFfO3TuD+Zx6vV5wTd
         saiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9bOe/JCswOnU7WdYHYnhxKuhHMqv5b1veFJCuFWhDL8=;
        fh=grh+l/l01Tfuw88bd6pzQP8VTuOQOiDQnVZvsS9R1x4=;
        b=AJVL06LAcr6OS96izUCZxv6auoVqloHfOQeUH9KG8BTcBbbkqWMPszhlw/QTTeiwFU
         XBHe+qmCnhglWJiJPhPCW3IZC0CszOLOMEi0Sxq283BS47HqOnskZKRv8IY79YFuyI9t
         Yzwu6EQh1p64bIisvFsRdpAIB3VsNZY3F9hCtr6v9eQlVT9dAiNAANtwSGdp5wZorOlo
         upnqyo++mFxUVN8f3nB/syCmW5D67jRaaPE4R0pc9mgVFQOEMWyLwAjxygX1UdHFQKcG
         b0HCUWDJTt4DY0uw+wYFA/tSahZjwwkbftc8bLq9wGiDCyPZyQ9J72N3P1yRXNiVzidG
         0A4A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tvSgedwL;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3df4a08eca4si1553275ab.3.2025.06.27.10.02.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 Jun 2025 10:02:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 52EEE5C6AAF;
	Fri, 27 Jun 2025 17:02:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 55EE2C4CEE3;
	Fri, 27 Jun 2025 17:02:17 +0000 (UTC)
Date: Fri, 27 Jun 2025 20:02:13 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Christoph Hellwig <hch@lst.de>, Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Robin Murphy <robin.murphy@arm.com>, Joerg Roedel <joro@8bytes.org>,
	Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?iso-8859-1?Q?P=E9rez?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?iso-8859-1?B?Suly9G1l?= Glisse <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, iommu@lists.linux.dev,
	virtualization@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org, linux-mm@kvack.org,
	Jason Gunthorpe <jgg@ziepe.ca>
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
Message-ID: <20250627170213.GL17401@unreal>
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
 <cover.1750854543.git.leon@kernel.org>
 <35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tvSgedwL;       spf=pass
 (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Leon Romanovsky <leon@kernel.org>
Reply-To: Leon Romanovsky <leon@kernel.org>
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

On Fri, Jun 27, 2025 at 03:44:10PM +0200, Marek Szyprowski wrote:
> On 25.06.2025 15:18, Leon Romanovsky wrote:
> > This series refactors the DMA mapping to use physical addresses
> > as the primary interface instead of page+offset parameters. This
> > change aligns the DMA API with the underlying hardware reality where
> > DMA operations work with physical addresses, not page structures.
> >
> > The series consists of 8 patches that progressively convert the DMA
> > mapping infrastructure from page-based to physical address-based APIs:
> >
> > The series maintains backward compatibility by keeping the old
> > page-based API as wrapper functions around the new physical
> > address-based implementations.
> 
> Thanks for this rework! I assume that the next step is to add map_phys 
> callback also to the dma_map_ops and teach various dma-mapping providers 
> to use it to avoid more phys-to-page-to-phys conversions.

Probably Christoph will say yes, however I personally don't see any
benefit in this. Maybe I wrong here, but all existing .map_page()
implementation platforms don't support p2p anyway. They won't benefit
from this such conversion.

> 
> I only wonder if this newly introduced dma_map_phys()/dma_unmap_phys() 
> API is also suitable for the recently discussed PCI P2P DMA? While 
> adding a new API maybe we should take this into account?

First, immediate user (not related to p2p) is blk layer:
https://lore.kernel.org/linux-nvme/bcdcb5eb-17ed-412f-bf5c-303079798fe2@nvidia.com/T/#m7e715697d4b2e3997622a3400243477c75cab406

+static bool blk_dma_map_direct(struct request *req, struct device *dma_dev,
+		struct blk_dma_iter *iter, struct phys_vec *vec)
+{
+	iter->addr = dma_map_page(dma_dev, phys_to_page(vec->paddr),
+			offset_in_page(vec->paddr), vec->len, rq_dma_dir(req));
+	if (dma_mapping_error(dma_dev, iter->addr)) {
+		iter->status = BLK_STS_RESOURCE;
+		return false;
+	}
+	iter->len = vec->len;
+	return true;
+}

Block layer started to store phys addresses instead of struct pages and
this phys_to_page() conversion in data-path will be avoided.

> My main concern is the lack of the source phys addr passed to the dma_unmap_phys() 
> function and I'm aware that this might complicate a bit code conversion 
> from old dma_map/unmap_page() API.
> 
> Best regards
> -- 
> Marek Szyprowski, PhD
> Samsung R&D Institute Poland
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250627170213.GL17401%40unreal.
