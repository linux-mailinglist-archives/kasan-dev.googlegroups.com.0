Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB35BVDBQMGQET3B3ZYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id D130DAFA33A
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Jul 2025 08:00:16 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4a38007c7bdsf59051511cf.3
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Jul 2025 23:00:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751781615; cv=pass;
        d=google.com; s=arc-20240605;
        b=e6hqROxNC5vLskDjYCtdtS0V7CsSXN5t9ulffn+mfOR7gy3Fno0DAAUlJMmg5zuojP
         xib0jW/oNZqbR9WU+zNkn0V+cBQJEZLitxB9wd0AxZWOZqawJyjU2UfHyRIWOCIrDPqC
         vb34R71kxntsu/uZskBhioDpANvrYFgjXxklqpdhMG6jR1gv6tuiHJz8Pt5fTlOAgIp4
         NqP6wL+IeR2y+IEBGuHxNb6oZgoynzK17L0uIdIguSXoF+tz32v9fZp05qg5rBn/SDw/
         txqEu2NcjUmrjZNmdULF6HlBmpDJS2FFHbGqjGmVrZhffIyJaa2y/diaMGJ1b0J6xZ+A
         yjow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ssvHWOyrL1Kpry4Z17AdkQYWPVrlFSojELEQXJz0PbM=;
        fh=z7Tpdc35ie1cun1XSn+juV2V5Of7EKqe1L2hnOEQnkQ=;
        b=Ao4eNSbt0iAq92Pdido9CTrZ7JUvatKgJbt4dIuKp/cGVTkmZsd5LulEOG+I79sLGI
         icVTINBayUEXkELbYFsYWrN2XvIOmw7Njut/YouYz+CdE/GZgTeSVH0jonYPUkl7CWyo
         MFXd0UNEdbsI70UVXg2zymdTUV5s9cl9h1jd4u9nTHs6E1XBNrlx1EPaGSsnIK2SSZxJ
         mSlT+hZ2SOzx4p68OCVVh+JbLzLy9wAzd+jT1vX3hYEbt8Ox/ZlKtnq6LLMPGIpzVMAv
         fZ2C/8h+utfCypfTO8m5wzlmXTefGRnpW8Nq/ax3J+cic7Vg8VDGLSaQODnJovBb4zor
         840A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rGudv65b;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751781615; x=1752386415; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ssvHWOyrL1Kpry4Z17AdkQYWPVrlFSojELEQXJz0PbM=;
        b=SzdvyPV+qILretelh5/ZEbEE0moqLbNUIHAGEBG/rWlr7XcfB+/jcEP09/r9uQdiJH
         hG4Che66TfLiOFyRma6GyRng39mSJ+cPYSnitiepswp4hcq8ztUdJx2sRC32M+aw169r
         gZQ0839pAkycM4nbHq5L8HLo2kgFfdmCPW0hPJo/1mLPDK/F+lQ/Oig+zspU2hDv2yBG
         mzdWweoJSBX87t0ursvgQNBDi5wYRntkw54s92BayHK4BL7lGwlb+untspIOWl0YUGOa
         wow1p56978GfzjLq/jGY7+16IKugnJF+ERdcvzHa217GBjDy01M6HD3lsDJuvZhf2yxc
         8Zxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751781615; x=1752386415;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ssvHWOyrL1Kpry4Z17AdkQYWPVrlFSojELEQXJz0PbM=;
        b=cb2/B597DKD/GNYCtnj8SVrvfyHFKCK1cG2/VNqRvGDptC7zQs3iYZZAb77LCZtUmJ
         UngWfhTe5+1G1sfOTOM4ikT1rbgB4vr4RTdCV5Vs04lMipIkbIReTR1EUG/WiCRzKiMS
         lLxZi8XpT/AsR1bkbnrW72GaVrcO+DPY8gHVGIeFdsnjss9/V6lYJEe3wwi+VWHoXsH2
         DvDj390fJA1L79E3y8hGVYmL3DJ62OvWnf9Wfa+r5ncHUs/+d8qDpikFL1EEo63r1IPr
         7/i9ViuOOXW1nGIfQ0OSi03hbCQxLGebsSTxiqLFFlkZJdzDi4VB3iB6xxy+3Rhe7/tp
         jhzw==
X-Forwarded-Encrypted: i=2; AJvYcCWYjvYFlmxKg0LkaMNz266UtyR3TgjW5Wzg+m1JAG6plnJnsecSpMKO+cgb+wdZu7gT126ZCw==@lfdr.de
X-Gm-Message-State: AOJu0YyG90cAKvcVH79wkmYpyC5nXiVuFwb3pV7I9y7mKwaaQSd1Egb9
	ss3TIF6XaBc5XrKYxikwOYm5LildtdpoTwjF2XIyWQRFNkZ7YB7nnLKE
X-Google-Smtp-Source: AGHT+IGvSlNO8BYJa99jMjB28vTbXS+az369OHYmNXuJNa8lnSXgZ5PeWZhiG+3wTuYWCX9HS+8evw==
X-Received: by 2002:a05:622a:1887:b0:4a8:225c:99b0 with SMTP id d75a77b69052e-4a9985e1ed1mr136508111cf.3.1751781615472;
        Sat, 05 Jul 2025 23:00:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeeZBqHwtj8tLfKGDUhJvNHJ8wtoZ8pCunqxWeNbdyvFQ==
Received: by 2002:a05:622a:3ce:b0:49d:9658:125 with SMTP id
 d75a77b69052e-4a99be49812ls34030041cf.1.-pod-prod-09-us; Sat, 05 Jul 2025
 23:00:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXgGIDsW8VGb44kSdBttUiCe1NhppPzOl+oa/HWRdM1mCpemBk+rnMcrvtY8gT1VKnLLlNoJyntYfk=@googlegroups.com
X-Received: by 2002:a05:620a:3705:b0:7d3:b957:cd0e with SMTP id af79cd13be357-7d5df0f275cmr837836885a.20.1751781612992;
        Sat, 05 Jul 2025 23:00:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751781612; cv=none;
        d=google.com; s=arc-20240605;
        b=aTgqM/F+MDz0LrxhhXdFy5l+gxCbqQduqhLl7vGCzCbW27kYZw99zCZVKjgwBscnlu
         0EgWf5m+/WWdZPHPtQUIrytC8G74tpTJcyujtA/juX8p+UgfguEs391pUrVczq8ySk2q
         rnsL+PWJcMFq2Li5EgjQrKIn1HpuCW39WBico1kjnimAymJSyUTEr76dkCaVrm6YhtWe
         IMWvhOkNoSIBGsKADnD2wc8vIAWBppaV8Ajl1S39ZiksbpF4BMgvzxvCiKnYwOkSMwKp
         DBlE7+Q71uJaQKbpzBI70urzn8RkJOcV0xxAyXyBJkhVbfWgf2Rp8K+qr5Pao0ziFgUX
         oy1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=fIoE9h1Ttmus+8dX+kExs7d3ndPa3iTpWbO6DspI45k=;
        fh=grh+l/l01Tfuw88bd6pzQP8VTuOQOiDQnVZvsS9R1x4=;
        b=Oxvf+EV4v3uQsMChmyC9PM6ztTH2+3ydRYtk2kB7yImAOtqKI6KVdZ+XFaXTRAw7Ot
         9P6M3VstVnZ26Yu+hhKBKB7zqRTZzaQ2nZ6VCLvUA+66L6jvhIh0C1ckGVyRxVzCEk05
         BhICYw13kQz7rO35kkkk0YKxRJGfUMbXNepGQCZ7EEaH1TdNzLhbHgG37ZMwEEFnQS+5
         sb7V+zeVMhJOZmlKtZwMFOGGn1j/iWy0kfnO3KXXmvLcZGdxROKhLvUPUiV4HAccop8O
         fccNePoS/K/3kQIH7+Eaen/XakReZAoNCN28flLmTUkoM1VpmvDBx/u/abBHLJJlfDMv
         C9TA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rGudv65b;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7d5dbce6d1csi23666485a.0.2025.07.05.23.00.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Jul 2025 23:00:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 697605C4B3B;
	Sun,  6 Jul 2025 06:00:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5853DC4CEED;
	Sun,  6 Jul 2025 06:00:11 +0000 (UTC)
Date: Sun, 6 Jul 2025 09:00:07 +0300
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
Message-ID: <20250706060007.GP6278@unreal>
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
 <cover.1750854543.git.leon@kernel.org>
 <35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
 <20250627170213.GL17401@unreal>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250627170213.GL17401@unreal>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rGudv65b;       spf=pass
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

On Fri, Jun 27, 2025 at 08:02:13PM +0300, Leon Romanovsky wrote:
> On Fri, Jun 27, 2025 at 03:44:10PM +0200, Marek Szyprowski wrote:
> > On 25.06.2025 15:18, Leon Romanovsky wrote:
> > > This series refactors the DMA mapping to use physical addresses
> > > as the primary interface instead of page+offset parameters. This
> > > change aligns the DMA API with the underlying hardware reality where
> > > DMA operations work with physical addresses, not page structures.
> > >
> > > The series consists of 8 patches that progressively convert the DMA
> > > mapping infrastructure from page-based to physical address-based APIs:
> > >
> > > The series maintains backward compatibility by keeping the old
> > > page-based API as wrapper functions around the new physical
> > > address-based implementations.
> > 
> > Thanks for this rework! I assume that the next step is to add map_phys 
> > callback also to the dma_map_ops and teach various dma-mapping providers 
> > to use it to avoid more phys-to-page-to-phys conversions.
> 
> Probably Christoph will say yes, however I personally don't see any
> benefit in this. Maybe I wrong here, but all existing .map_page()
> implementation platforms don't support p2p anyway. They won't benefit
> from this such conversion.
> 
> > 
> > I only wonder if this newly introduced dma_map_phys()/dma_unmap_phys() 
> > API is also suitable for the recently discussed PCI P2P DMA? While 
> > adding a new API maybe we should take this into account?
> 
> First, immediate user (not related to p2p) is blk layer:
> https://lore.kernel.org/linux-nvme/bcdcb5eb-17ed-412f-bf5c-303079798fe2@nvidia.com/T/#m7e715697d4b2e3997622a3400243477c75cab406
> 
> +static bool blk_dma_map_direct(struct request *req, struct device *dma_dev,
> +		struct blk_dma_iter *iter, struct phys_vec *vec)
> +{
> +	iter->addr = dma_map_page(dma_dev, phys_to_page(vec->paddr),
> +			offset_in_page(vec->paddr), vec->len, rq_dma_dir(req));
> +	if (dma_mapping_error(dma_dev, iter->addr)) {
> +		iter->status = BLK_STS_RESOURCE;
> +		return false;
> +	}
> +	iter->len = vec->len;
> +	return true;
> +}
> 
> Block layer started to store phys addresses instead of struct pages and
> this phys_to_page() conversion in data-path will be avoided.

I almost completed main user of this dma_map_phys() callback. It is
rewrite of this patch [PATCH v3 3/3] vfio/pci: Allow MMIO regions to be exported through dma-buf
https://lore.kernel.org/all/20250307052248.405803-4-vivek.kasireddy@intel.com/

Whole populate_sgt()->dma_map_resource() block looks differently now and
it is relying on dma_map_phys() as we are exporting memory without
struct pages. It will be something like this:

   89         for (i = 0; i < priv->nr_ranges; i++) {
   90                 phys = pci_resource_start(priv->vdev->pdev,
   91                                           dma_ranges[i].region_index);
   92                 phys += dma_ranges[i].offset;
   93
   94                 if (priv->bus_addr) {
   95                         addr = pci_p2pdma_bus_addr_map(&p2pdma_state, phys);
   96                         fill_sg_entry(sgl, dma_ranges[i].length, addr);
   97                         sgl = sg_next(sgl);
   98                 } else if (dma_use_iova(&priv->state)) {
   99                         ret = dma_iova_link(attachment->dev, &priv->state, phys,
  100                                             priv->mapped_len,
  101                                             dma_ranges[i].length, dir, attrs);
  102                         if (ret)
  103                                 goto err_unmap_dma;
  104
  105                         priv->mapped_len += dma_ranges[i].length;
  106                 } else {
  107                         addr = dma_map_phys(attachment->dev, phys, 0,
  108                                             dma_ranges[i].length, dir, attrs);
  109                         ret = dma_mapping_error(attachment->dev, addr);
  110                         if (ret)
  111                                 goto unmap_dma_buf;
  112
  113                         fill_sg_entry(sgl, dma_ranges[i].length, addr);
  114                         sgl = sg_next(sgl);
  115                 }
  116         }
  117
  118         if (dma_use_iova(&priv->state) && !priv->bus_addr) {
  119                 ret = dma_iova_sync(attachment->dev, &pri->state, 0,
  120                                     priv->mapped_len);
  121                 if (ret)
  122                         goto err_unmap_dma;
  123
  124                 fill_sg_entry(sgl, priv->mapped_len, priv->state.addr);
  125         }

> 
> > My main concern is the lack of the source phys addr passed to the dma_unmap_phys() 
> > function and I'm aware that this might complicate a bit code conversion 
> > from old dma_map/unmap_page() API.

It is not needed for now, all p2p logic is external to DMA API.

Thanks

> > 
> > Best regards
> > -- 
> > Marek Szyprowski, PhD
> > Samsung R&D Institute Poland
> > 
> > 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250706060007.GP6278%40unreal.
