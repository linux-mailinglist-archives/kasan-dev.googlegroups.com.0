Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBMOA5TCQMGQE7HR4EWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3144EB4604F
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 19:38:59 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-319c9bb72e1sf3673451fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 10:38:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757093938; cv=pass;
        d=google.com; s=arc-20240605;
        b=XyzwcgTGEloXs0xtd55vw54S04sKl5BOeMnQJq5/7wm1AjeLdqx427cN9BJRcFQsJL
         psgz6yMgrvWdylRpBGKCf2XT3P/p+v1zeEuCsvxzOUuejci5+/HU9Ou6HNuve1B15gr4
         TWi0mS9CLKbKt1fM1cuDu2mHnTJtorbr2wnKx/jpSAbiFFnXUfM6xH4htravFagginCP
         YB912bc3M6I9huD9kOL4E/WQgiKKjeYiEySJv+pdkikdYVTfRQA+myAJFefyrk8FBQS4
         x+PNTiPH+pKC6CCiVchx65lcLefide3fUHqktPjsCcLL0gPMiGQwemxGpl0Ox/vte2+B
         4Yew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=tq1ChFyTT3jTQbMtrJyClp61nei/SQ0AaxhMAI8F0VQ=;
        fh=5sr3+9NGs68lLm0XDkHELFlGg1f72rdAa3Gd7WGA+Y8=;
        b=FGULf4m/RJ6zDtv8XchYmuUvDV6wZlEwMw1AXfUqGAwF4VCSd/PKG51vYZGcNQR7it
         qxlakXAG2K9PXt+QLr1Jm7nFIsEsFGYsfrEF5f9Y7xAprdHHDJjfgUzh2O18ACupSwAE
         HZ3PZlTufTKLUko+mXTRhOZLVUtc1Eb5HD/97qA66+O6w4B01kbKC+rrG7G6ylNGWFH9
         fl1eCDTI6dpVPlQSuShzehwbpRKdd3vd3DpryYr8jIeIwWHKkaCM7XGz3PESYZSV4/AH
         kBF60MpkLFvLgU7u5yFdP7AZb6y/UAag4IEjDh9TLBQB6/G/XivSyVlans9Eba3mUID0
         5fCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Ld3/+CXF";
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757093938; x=1757698738; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=tq1ChFyTT3jTQbMtrJyClp61nei/SQ0AaxhMAI8F0VQ=;
        b=K85nRWvMS8E2ZvvVu+l7b2gp2DGlKS2nCtutroHSIWTbXQv5xTT8o1tm3BH7vvWgxD
         bqqJ/p0I7gnrlbVc/rxUlcGSrMAh+L894AY2mdeuc4NBz0gT/2rgE7EgDCPO79OJa8IN
         jggUgrUzbnvVfkMk5vvwSnUeNL2gGNRvMsk0sTlAR8WnVeyx7/qxEi5FZ01UjqW5uauA
         KJuM+5lpIACTgCQ8EKcZ+/HZgzIW/mSyJ10T4IKSRYIB6Y6rS/r/9DeRcnNNf/rDm0o8
         nM+98RezYRRo6tDFI2i5Z+VdJIUv5FptUsnEZT8k9q2+RremQr9vdkP4hBoY3MKeipUZ
         GueA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757093938; x=1757698738;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=tq1ChFyTT3jTQbMtrJyClp61nei/SQ0AaxhMAI8F0VQ=;
        b=QbhYfh3z6IqjDtGeJ+stqHKxCjrZmnql7h1uWBy71SdYXx1X9C2F8ptp+M5gS5jwsO
         M9Ae9sLrEPdvmfoBQ1jme/fT3i7JJFqWYTFeoQmtB7GQ4prGuM9cfgTbBzEx+6VlVhtF
         UI2zOThdt0IBNRBZTSGFgcST54oqqebjKOkTAaIkCxDKWLiwzPfmiZQuNAWlVY7VphPm
         FPdC7XqXjFbvERZvMa/jdFw9Yg1KBlgqmAk8i1jt+OYsLQRYVNFlMdaD43yfUNTatvib
         Phy7zfyMrdJHSY7ySyHDjYYdU8d/xJV2MAGO3sDfl0H8rE/unwigCi7/h3bIsYP7xhZ0
         +kEA==
X-Forwarded-Encrypted: i=2; AJvYcCXYitLGJ1Ip3F/6KRwhicHhF7ZixH01RXqin+9hBOuQAZBj8GuSug83zDIw6JD+oaO98YnkwA==@lfdr.de
X-Gm-Message-State: AOJu0Yw/paBvUu5MCqRIGLfeiIhH91dzoFzvGA00jbPpgS7MmHTxNvum
	5opIAURnunG1TW3DrvFtqOUxZpp9f0szeVkYAjQIyKTte+JPKkIoVNwT
X-Google-Smtp-Source: AGHT+IHdeAYMtGWmjJmmF4Q9RWBvkFtSmU29xzexI1NMBCjpxmcnmjup4N14zr+XneJXSWt/yJn73A==
X-Received: by 2002:a05:6870:fb87:b0:31d:6a5b:c6f0 with SMTP id 586e51a60fabf-31d6a5beea6mr5612648fac.0.1757093937783;
        Fri, 05 Sep 2025 10:38:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcBx5/m0Jr9oybdJmhKPnau4JeKPkmizVpKj2prsjwrDQ==
Received: by 2002:a05:6871:c711:b0:319:c528:28df with SMTP id
 586e51a60fabf-321271cc521ls620855fac.1.-pod-prod-08-us; Fri, 05 Sep 2025
 10:38:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/Bi8xZSvrRRz6aosPdUHzxYIyffaRR8dzCrep4MjdxxTJ9JMjU84doPGfeVnC9fynVGJMnkEhh7M=@googlegroups.com
X-Received: by 2002:a05:6808:3099:b0:439:b198:23ab with SMTP id 5614622812f47-439b19828f0mr1722749b6e.18.1757093936551;
        Fri, 05 Sep 2025 10:38:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757093936; cv=none;
        d=google.com; s=arc-20240605;
        b=gIQTieIL+WB3WnyVH7UlKWEoS9WfEl9aGKHoO55B8g4hox3QIplutfdrv2PhpyLHkS
         RYEQy1GU6RcWu09JCPppp81usbwNPscO75Lvcg1Yd7EmHcenI77OzYuy1SE2NUeI8Nho
         Hv1qAuGJdtkwBxlaR96cUzX+n8/L/qmnjyR8ZGRY6hXmTOl+PQyr3VPUCCcHtZIgadny
         7xJ6+gSj1crTRsBgOUFQAi+CQzLF2z1TupIPiBJy3fLm0TjLKIGxP0XPv1JtyR59Qfo9
         AKCw8MH2GeaYTg4knyY+JIe5ScnEgh8ZUhcV/wnm2iB8nVAeGrYU9/yBFahXxBMrNcO1
         eUaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Q2ZdB7VokBOK/lOhO1dUKgUR3rSn7R22gOZYkbmWGWQ=;
        fh=iu7vSg1EzzlrRbrwbQPzfF0RoV1Uw6GXAom/pnqIJaQ=;
        b=F+SMPJbexyq2SLaAKkDXeMNeOPqeAuhe7mYy69ieTKbgENdA+6RALJpTrA10uoa/0A
         kxbVgw/yvhI2eTisUOvnPREmoCrWISIX18r9ZhK1NXkEbWTxvUnQYS/2O/3DLGFyzMRU
         K5NpPrXnouam6YdIh1AxhiS6e0qNe3lJVF3E5HhGKjmeh3XmGTeRGqZuyW9sMWxu3n6D
         gK7OzLe/pszLcNGEUFpz4wAtqDl81QSwkshthAfbfjq0TjzDRBE+ae9dMKN6aOjU12Xb
         LNtNgY9lzNLO+V/4SytNvNiTIop2eEWzQBmO2+rmUOMkd15t0cmkz2GQWc7dyGCZ/yYJ
         JDcw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Ld3/+CXF";
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-437ffecff61si141139b6e.2.2025.09.05.10.38.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Sep 2025 10:38:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 7274460218;
	Fri,  5 Sep 2025 17:38:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4AA22C4CEF1;
	Fri,  5 Sep 2025 17:38:54 +0000 (UTC)
Date: Fri, 5 Sep 2025 20:38:50 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: Re: [PATCH v4 00/16] dma-mapping: migrate to physical address-based
 API
Message-ID: <20250905173850.GB25881@unreal>
References: <cover.1755624249.git.leon@kernel.org>
 <CGME20250829131641eucas1p2ddd687e4e8c16a2bc64a293b6364fa6f@eucas1p2.samsung.com>
 <20250829131625.GK9469@nvidia.com>
 <7557f31e-1504-4f62-b00b-70e25bb793cb@samsung.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <7557f31e-1504-4f62-b00b-70e25bb793cb@samsung.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Ld3/+CXF";       spf=pass
 (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted
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

On Fri, Sep 05, 2025 at 06:20:51PM +0200, Marek Szyprowski wrote:
> On 29.08.2025 15:16, Jason Gunthorpe wrote:
> > On Tue, Aug 19, 2025 at 08:36:44PM +0300, Leon Romanovsky wrote:
> >
> >> This series does the core code and modern flows. A followup series
> >> will give the same treatment to the legacy dma_ops implementation.
> > I took a quick check over this to see that it is sane.  I think using
> > phys is an improvement for most of the dma_ops implemenations.
> >
> >    arch/sparc/kernel/pci_sun4v.c
> >    arch/sparc/kernel/iommu.c
> >      Uses __pa to get phys from the page, never touches page
> >
> >    arch/alpha/kernel/pci_iommu.c
> >    arch/sparc/mm/io-unit.c
> >    drivers/parisc/ccio-dma.c
> >    drivers/parisc/sba_iommu.c
> >      Does page_addres() and later does __pa on it. Doesn't touch struct=
 page
> >
> >    arch/x86/kernel/amd_gart_64.c
> >    drivers/xen/swiotlb-xen.c
> >    arch/mips/jazz/jazzdma.c
> >      Immediately does page_to_phys(), never touches struct page
> >
> >    drivers/vdpa/vdpa_user/vduse_dev.c
> >      Does page_to_phys() to call iommu_map()
> >
> >    drivers/xen/grant-dma-ops.c
> >      Does page_to_pfn() and nothing else
> >
> >    arch/powerpc/platforms/ps3/system-bus.c
> >     This is a maze but I think it wants only phys and the virt is only
> >     used for debug prints.
> >
> > The above all never touch a KVA and just want a phys_addr_t.
> >
> > The below are touching the KVA somehow:
> >
> >    arch/sparc/mm/iommu.c
> >    arch/arm/mm/dma-mapping.c
> >      Uses page_address to cache flush, would be happy with phys_to_virt=
()
> >      and a PhysHighMem()
> >
> >    arch/powerpc/kernel/dma-iommu.c
> >    arch/powerpc/platforms/pseries/vio.c
> >     Uses iommu_map_page() which wants phys_to_virt(), doesn't touch
> >     struct page
> >
> >    arch/powerpc/platforms/pseries/ibmebus.c
> >      Returns phys_to_virt() as dma_addr_t.
> >
> > The two PPC ones are weird, I didn't figure out how that was working..
> >
> > It would be easy to make map_phys patches for about half of these, in
> > the first grouping. Doing so would also grant those arches
> > map_resource capability.
> >
> > Overall I didn't think there was any reduction in maintainability in
> > these places. Most are improvements eliminating code, and some are
> > just switching to phys_to_virt() from page_address(), which we could
> > further guard with DMA_ATTR_MMIO and a check for highmem.
>=20
> Thanks for this summary.
>=20
> However I would still like to get an answer for the simple question -=20
> why all this work cannot be replaced by a simple use of dma_map_resource(=
)?
>=20
> I've checked the most advertised use case in=20
> https://git.kernel.org/pub/scm/linux/kernel/git/leon/linux-rdma.git/log/?=
h=3Ddmabuf-vfio=20
> and I still don't see the reason why it cannot be based=20
> on=C2=A0dma_map_resource() API? I'm aware of the=C2=A0little asymmetry of=
 the=20
> client calls is such case, indeed it is not preety, but this should work=
=20
> even now:
>=20
> phys =3D phys_vec[i].paddr;
>=20
> if (is_mmio)
>  =C2=A0=C2=A0=C2=A0 dma_map_resource(phys, len, ...);
> else
>  =C2=A0=C2=A0=C2=A0 dma_map_page(phys_to_page(phys), offset_in_page(phys)=
, ...);
>=20
> What did I miss?

"Even now" can't work mainly because both of these interfaces don't
support p2p case (PCI_P2PDMA_MAP_BUS_ADDR).

It is unclear how to extend them without introducing new functions
and/or changing whole kernel. In PCI_P2PDMA_MAP_BUS_ADDR case, there
is no struct page, so dma_map_page() is unlikely to be possible to
extend and dma_map_resource() has no direct way to access PCI
bus_offset. In theory, it is doable, but will be layer violation as DMA
will need to rely on PCI layer for address calculations.

If we don't extend, in general case (for HMM, RDMA and NVMe) end result wil=
l be something like that:
if (...PCI_P2PDMA_MAP_BUS_ADDR)
  pci_p2pdma_bus_addr_map
else if (mmio)
  dma_map_resource
else              <- this case is not applicable to VFIO-DMABUF
  dma_map_page

In case, we will somehow extend these functions to support it, we will
lose very important optimization where we are performing one IOTLB
sync for whole DMABUF region =3D=3D dma_iova_state, and I was told that
it is very large region.

  103         for (i =3D 0; i < priv->nr_ranges; i++) {
  <...>
  107                 } else if (dma_use_iova(state)) {
  108                         ret =3D dma_iova_link(attachment->dev, state,
  109                                             phys_vec[i].paddr, 0,
  110                                             phys_vec[i].len, dir, att=
rs);
  111                         if (ret)
  112                                 goto err_unmap_dma;
  113
  114                         mapped_len +=3D phys_vec[i].len;
  <...>
  132         }
  133
  134         if (state && dma_use_iova(state)) {
  135                 WARN_ON_ONCE(mapped_len !=3D priv->size);
  136                 ret =3D dma_iova_sync(attachment->dev, state, 0, mapp=
ed_len);

>=20
> I'm not=C2=A0against this rework, but I would really like to know the=20
> rationale. I know that the 2-step dma-mapping API also use phys=20
> addresses and this is the same direction.

This series is continuation of 2-step dma-mapping API. The plan to
provide dma_map_phys() was from the beginning.

Thanks

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250905173850.GB25881%40unreal.
