Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBOFK63BAMGQEWBAWGJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id BD383AEA59B
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 20:45:17 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-70e5e6ab756sf20501137b3.2
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 11:45:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750963513; cv=pass;
        d=google.com; s=arc-20240605;
        b=P4Q4fu2Wb7jjlCMmnZWSTidowHPN/40Y6A85AY4gYp+L0/z44Jiqx0PZGMv4A1JJ7o
         ATWK6F+C9IHk7FZonAqgcq6YBTi2fLoYzB2Q5foFXsYL6WhfeT32gZFjwt2z4RUAz366
         rcArSgZFtKQQHmHsC5JXpdp0+9GYRe8BVYTA2rnAP2r44Dqli3leTgKtDMrBBaVrS8v7
         uiMRVUPH8kfM1VhHAI/1jzki6fsqoMN2eMSWruiPphvNWYMxJZV6wtozvYOn6S2UJQrK
         eG1b6FWjy2GJ7XIpPoNszl1EuBQMQgpTlP1YQMXazOyxEVA8MMPMYsH+9yNVLTy6j7hB
         veJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=lz7G2ligToznLgEGzbRIOpVB7m1zVka1bMUYrH+ED0k=;
        fh=cxji9ZMMB/0zE9dCcK7p6qdLXex61B/HKCKvOzYhImU=;
        b=asr9pQ7675Tv9oRR4BculRa1IF/1wDoiV/2nYafJMwTyTR8wgp1F8p3HT+klnqGu8l
         pNLXwL0kzVwdffAUU9xXQX/hatj0MPJ7o72/Y9A2bhSwlVv5mvTPqEpz3toBv+zi757w
         8we3eP5etcyLi6+XfSLdXg6NBNuFcYdjkl/Flc4yFtqBqSV55S3e2LZ/dpVgwgP/3TcG
         SXP2Mx9TtdTGQH/tVAJUZ/6ukYVf6feo9ImpWZthxGfB2gGxpNQIKIkLB12YzmPOkuXk
         //i3/1xqSuwMspg+kBWV+RLpgV7WBy+He+byYkJ2pXRcU9/BBAEajRqaoUtHc4BiF/cr
         c2QA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hLP472CC;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750963513; x=1751568313; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=lz7G2ligToznLgEGzbRIOpVB7m1zVka1bMUYrH+ED0k=;
        b=SRzvR09Kv8O/Ey1hVW6pjfpcrxMw2h6w3LLN4LE3UKrpTTF7kVBxH9J/7OrcLFTd9H
         QJQJbe0E1vfBZcKNYnr1+tvFb/R05WCaQw67Ow4YTyc/Dr+kd2iKWgK5fTPgmPZotuPz
         AANwUfTbiLS5QxouMetEGviGYTY8Ccj1g+thKMp+OHcTZGJbS+hn29LjTJBGfh/IWKDo
         oBjizbj2xaZo6MC+GrfSJWxek0nH/g9P7CKqNWfmvbFiyFLcExgLfJdtxOp+GwSZqz1r
         fvS0lih8dhQXGXxDShpiQfU62cNdHElOwCDvWAkpB8ncTCKu6057oajpo0vTtf1jIMAX
         /FIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750963513; x=1751568313;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=lz7G2ligToznLgEGzbRIOpVB7m1zVka1bMUYrH+ED0k=;
        b=mIWXDaJKHcgoGeAwtoatCeskDHuReTrezszuajlRHh9Bg9tlIVtNJwKH/tGC9mUAYj
         ylZEgT9qF/fylCgeSO2lVtRSxfvEOmADAggmyU0NHsnSFlxjftQM1lcE4INNzBnNG6v+
         Y8nJTK6e/+dJadB6r/dWd3AgeotfI9qPql0ZvGYhwtk/Og2jLcmBlCZdqTAj2xDgAF3A
         Zv8jOrtsjuaiv6t/rpsppqN+A85xFcqLN1+MV+W9LomN69Qd4VTaTyzjeMJcHLZbQmrD
         veTlJ3dl+NyROIB8XgSGtn1BkC7yR/LZKZG6OUyWQNh4liOjzRzQWFAezcBhGWcNZfTE
         3y6A==
X-Forwarded-Encrypted: i=2; AJvYcCXhT72BLF3Sc6fj2nMUrhcoDmvgB1ZEEMw9CspoMiaplsHLJovfYrV/EDWiAjAHSE4nYwbqbg==@lfdr.de
X-Gm-Message-State: AOJu0Yx8Spx4bvvjgODd8MOoCqiOngOctQFLwcalt67RHDxrj+bj2Zg+
	ZDpNoSvyyU6zqXfHNgHx3Jsaqg7GfibUxMyBpwFuMUX+Z1whb/l0pDhM
X-Google-Smtp-Source: AGHT+IHNuodhxk0/pVKM8X54SFhk6zr62/3mmcVNMqTd9ppjowXRDoR2kpKslYDOp2KLZ0egRaHlRw==
X-Received: by 2002:a05:6902:1891:b0:e87:a83d:9448 with SMTP id 3f1490d57ef6-e87a83d9769mr232893276.29.1750963513338;
        Thu, 26 Jun 2025 11:45:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeAEZp59q0GCoNKFwlX3vcQ3je3gKgcurMMQE9nlyI1gQ==
Received: by 2002:a25:e906:0:b0:e82:574d:5f with SMTP id 3f1490d57ef6-e879c3bf685ls1573572276.2.-pod-prod-05-us;
 Thu, 26 Jun 2025 11:45:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUNLBQoEXGx/IMlw9wfIx1BEVogC/1xLh4itiGc5Q/2bhvv3L6RD/gP8ZrnUDWQr7T+ZNXMwXnf4t8=@googlegroups.com
X-Received: by 2002:a05:6902:18cc:b0:e7d:7e4a:24db with SMTP id 3f1490d57ef6-e87a7ad3082mr669797276.9.1750963511280;
        Thu, 26 Jun 2025 11:45:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750963511; cv=none;
        d=google.com; s=arc-20240605;
        b=VaFBasUEPRvP0FNQeWGunPYovbsZb0dQXT3m34Oft4FvII/+5ubrrDA0WpyOcDh3+J
         WkSLzxxunxfExTjN4ewZGJBIhYf2GSIwPnHZhLXbf6nzrnwzizl9fUUyp/9g1Qhk7HK0
         e8eHNQEvR5I1oo4ycOvxOawYXe4b8tTuuotoV3AsXLOIGb7fbg/1eI6tiyl460Xc6+hZ
         e1vx+1bgaexduqYy0OObvYXdFRnMpJxykWrbnL7pxU1oajuSkPEibZrTk1K0i1c27Ztl
         Q0ZfRyErwejr4Tq1TiO8qdNrjQLxVmFrwYrgsG3q8nGWlMoNqU1YzAbK1QWlzHzbLi3M
         o8GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=zqOZ0nvJoY2kvs0ans1k/jor+XKnKoBEFfFm8tFXKgw=;
        fh=qhfMinULXlSToGflKj7IzvxAJCN117VRSl/HkOgACOU=;
        b=bswscvrkmZ4ToQkurBWNac4Dp9VRUYtyi1O4s1A8amhODnRaqWQt4VfQ42cZQwMCt9
         679ODl5du3+bpp0Ly7zqCDiGH2+oNF3GVTwEjfzJugDwJZbSnAKbX91nxkrqoFu+IWz0
         cmlrwaDw9WmZ/eg5TZKWRnjNaybVJbDKA9NhSUf1b7aBAjbosJMev3PVDsigbwtyh57E
         Q4zVuekpRJbgXwD3agfdgbi5qonQrTdmx/RWss5N6XLNLflksKuTaJvlnApyc8QcGHnN
         QPCnIOwu9YHWpLFrz5qto27h9IJC0TEcgmffwd6Ym4skCanrhr6bC4SnxIWZkgkfHS6R
         MyxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hLP472CC;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e87a6c03846si32819276.3.2025.06.26.11.45.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 11:45:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id A3BCB4375D;
	Thu, 26 Jun 2025 18:45:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CC281C4CEEB;
	Thu, 26 Jun 2025 18:45:08 +0000 (UTC)
Date: Thu, 26 Jun 2025 21:45:04 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Christoph Hellwig <hch@lst.de>, Jonathan Corbet <corbet@lwn.net>,
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
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?iso-8859-1?B?Suly9G1l?= Glisse <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, iommu@lists.linux.dev,
	virtualization@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH 5/8] kmsan: convert kmsan_handle_dma to use physical
 addresses
Message-ID: <20250626184504.GK17401@unreal>
References: <cover.1750854543.git.leon@kernel.org>
 <cabe5b75fe1201baa6ecd209546c1f0913fc02ef.1750854543.git.leon@kernel.org>
 <CAG_fn=XWP-rpV-D2nV-a3wMbzqLn2T-43tyGnoS2AhVGU8oZMw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG_fn=XWP-rpV-D2nV-a3wMbzqLn2T-43tyGnoS2AhVGU8oZMw@mail.gmail.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hLP472CC;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Thu, Jun 26, 2025 at 07:43:06PM +0200, Alexander Potapenko wrote:
> On Wed, Jun 25, 2025 at 3:19=E2=80=AFPM Leon Romanovsky <leon@kernel.org>=
 wrote:
> >
> > From: Leon Romanovsky <leonro@nvidia.com>
>=20
> Hi Leon,
>=20
> >
> > Convert the KMSAN DMA handling function from page-based to physical
> > address-based interface.
> >
> > The refactoring renames kmsan_handle_dma() parameters from accepting
> > (struct page *page, size_t offset, size_t size) to (phys_addr_t phys,
> > size_t size).
>=20
> Could you please elaborate a bit why this is needed? Are you fixing
> some particular issue?

It is soft of the fix and improvement at the same time.
Improvement:=20
It allows direct call to kmsan_handle_dma() without need
to convert from phys_addr_t to struct page for newly introduced
dma_map_phys() routine.

Fix:
It prevents us from executing kmsan for addresses that don't have struct pa=
ge
(for example PCI_P2PDMA_MAP_THRU_HOST_BRIDGE pages), which we are doing
with original code.

dma_map_sg_attrs()
 -> __dma_map_sg_attrs()
  -> dma_direct_map_sg()
   -> PCI_P2PDMA_MAP_THRU_HOST_BRIDGE and nents > 0
    -> kmsan_handle_dma_sg();
     -> kmsan_handle_dma(g_page(item) <---- this is "fake" page.

We are trying to build DMA API that doesn't require struct pages.

>=20
> > A PFN_VALID check is added to prevent KMSAN operations
> > on non-page memory, preventing from non struct page backed address,
> >
> > As part of this change, support for highmem addresses is implemented
> > using kmap_local_page() to handle both lowmem and highmem regions
> > properly. All callers throughout the codebase are updated to use the
> > new phys_addr_t based interface.
>=20
> KMSAN only works on 64-bit systems, do we actually have highmem on any of=
 these?

I don't know, but the original code had this check:
  344         if (PageHighMem(page))=20
  345                 return;

Thanks

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250626184504.GK17401%40unreal.
