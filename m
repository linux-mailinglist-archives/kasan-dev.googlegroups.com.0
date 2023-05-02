Return-Path: <kasan-dev+bncBCLL3W4IUEDRB6HJYWRAMGQEQQNAZRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id ED14C6F4B72
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 22:39:20 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-50bc1a01cffsf3247634a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 13:39:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683059960; cv=pass;
        d=google.com; s=arc-20160816;
        b=NPPMiK8l81mLmM4pB4AU8Xo7rjPmb0FWgiJsvD1wzYtZzlwKS6oNVVkhDL3mB59Ubs
         q3Fs0XRw8A8Vm7kzZsnMsCEji1fHA59SqXRo1inrmzEnQchoE0GyB6MI3MHOGusOCZeT
         K3S8+AZOu7q0DGwNxPvjLy7gq+g74ZaRbLVJnmNB/Pdh9jxKMX3UrDNZ4RtdtgbT8QPI
         hVbMig+FZwsa5SLsaqvIBD5VlG5mUzXQj2rfpVXL0RBN3r/LgihNgj8IiLTg/YrKkUnt
         k6tBr4pLOlQdvX5/Y3lOqnhJEgh/s7uLZ/rE9Bt+07re54Vs7A96OEHYXfOSJrB4WQTT
         rSsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=pi1Vz/oPc6HTMS2bWHUpUohRf9syaWqJ8DCZ6r74V2I=;
        b=pEdOrleDHFtiiBSMS9gaiMsCOLmlRmBiHGm6aFLmVwX5VOI+SgWT27Q0BslYOQ4QDG
         tw6683j0mopLY8i1w9dVmunL6WB+3HVzUpuqtuMzQ+ojNpMkz5wbXonf6dOsBX678hNB
         c9Ar2udulXzbsMfTrfaK/L2yUP5+ZOLyG+C6tT4YH8UShxhC5o9XdUGuaNggfqAv25E3
         seGSGPlJNDVQWtylt4ivoftP0Zme1D2KFbwvtY8naxGq5yD9IMZzpoO0dGJw0PREG+wR
         X9QWb9dGVe+NyQAHQOMKKvQF6cFKOhM+TTTh0ms1AgHHSTdngrCWCSx/41HG0lWu8HjN
         BWjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=4A680Ynb;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683059960; x=1685651960;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pi1Vz/oPc6HTMS2bWHUpUohRf9syaWqJ8DCZ6r74V2I=;
        b=G7iXSKWSllxVy3dNZ93jmP7g9EspavTtzJodJfBe80MsUW6GKeonNt2SANyINzzkAC
         7ve5DLlXzJ7C9V8KqoExKZ539MerwTdWQKXEVm5gS67iSsjNeEPLUEL56TJJ6mcARlzg
         6wM9f0DjVAzoLNYHt3MkFqz7a4xU05E/lC21njH6+v6F1cUhGIcQcrCYywqGKdl2DcLl
         bgAfxYk10rmeWw30gXFkLCK8ojccH0P8U/yKwqPibQyLphaPLg5/OLPikmv8j7MYkgjz
         PQft2s5Q2xU0C4axy5Urr4RAmcDKe5c8WE2Yp/X5Nd/CEpdi/cHOlo8UsbCp//fnQ8da
         Vkvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683059960; x=1685651960;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pi1Vz/oPc6HTMS2bWHUpUohRf9syaWqJ8DCZ6r74V2I=;
        b=RYC26ItN1jkb3phPNUck8QFW9QBqELS7WPpnhPgl46iRgH1WjsZVxQ6S24dQX26vTp
         KQaSWHczAtt6hL6/7zQevle2A99T4wFK2UmNjniVTA/s1+E1P+IFzh54QITvf5GMNcYQ
         VxrUmpkudcLQP+tq7QnhvKCShcLYy3qMuINAWgSVU3i0PdyS9YKM6I7ZRUfGFnV84TFG
         aX01Xj4zGt5zahHlr2Sqw+FoRUKeuRuF0fiV0pTucZodnMIyDRCOVtXeU/NuXC+r1kPZ
         uPqSpoSWezvSTleFR5lfCEQEZk7uWrZxQ3ZPqaJKRObs89eqlBr46YXWaMqJUWwt8n6t
         qTVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDw9SiHwajzC8czwbTJzKJEGxAnlib5D1eK76AOaME8rt6hYkezA
	Z1u/qHyNvdgufjOAMb/Kqc0=
X-Google-Smtp-Source: ACHHUZ6gmHgnjCnrEpuub9kM/So5BkzKYWkHZuhrYkM0ptwX6fVHBSqVdEgAd7hbzdtKd+R22Zfw8Q==
X-Received: by 2002:a50:8711:0:b0:50b:caf8:776c with SMTP id i17-20020a508711000000b0050bcaf8776cmr2017403edb.6.1683059960371;
        Tue, 02 May 2023 13:39:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:35c7:b0:50b:c404:41f5 with SMTP id
 z7-20020a05640235c700b0050bc40441f5ls5913881edc.0.-pod-prod-gmail; Tue, 02
 May 2023 13:39:19 -0700 (PDT)
X-Received: by 2002:a05:6402:12c1:b0:506:c41c:bd14 with SMTP id k1-20020a05640212c100b00506c41cbd14mr8934503edx.33.1683059959193;
        Tue, 02 May 2023 13:39:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683059959; cv=none;
        d=google.com; s=arc-20160816;
        b=GmdvwLSDcMh9DxWr4tbT7ziylDuaCzfDJmFRbu5800J1mCi/t7/H0MjXHZTSya7UDo
         0goTefHtC50MmERYnxSQrvAQF2HheEfJlrfjx1D/VHb8GsMIAQd1bMmu0eawk0L8aWlt
         N8msn3/eXf8JPwoujkzZiJ8n+lorsA3vvwXZ2lwTE1c5eKqFMaPfyUgExH3pScVNOgGr
         R4UWcTGNjhN1DCHq8or5VX++cp/S+188DTNh3xGI9XASZYVy9h91cVQDn+CjVBSoVZKY
         /2cn8qTexllIkkEm6lva2yXe0MxwetcxlNT0pSnuGh5Hea9Ur0djaDZ4M2X5PCCCt93J
         N1wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5QTV5xnoiRBjQvyvs/qzikvLN+OGMMKt2LrDUuupFJg=;
        b=iJGM4sOknNGuPId+j1GkX9SbWoxz30avHUMcVBDWUxjDe8piYohtLmqtl8Kqa+E6BW
         ewkLUldNnE9jYpIEXBSW0Z93ysvHvVFIv/Tj14d7pmrwRCKI0sIuQLlhHdS2Xy7NuX6r
         BLZRZCNNVPRZswTW/DaYAtnEJwwboP1QfwH+2P4C3JZq3xx5yz1resjW44eariEIv/j0
         RlAlQCetMKsS+aQD2I6XvWYzPibf2VtzcCzu57IDrdXfRoebE/8MSe0VruR+BkhhQXS/
         HDDD0U8qybRdOIiuicMVD6GYRRSuClE+4aVskPc4t9LxgttaevmGG9jaFuyT9x4gp+av
         GMqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=4A680Ynb;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [2a03:3b40:fe:2d4::1])
        by gmr-mx.google.com with ESMTPS id g9-20020a056402090900b00506bc68cafasi1494008edz.4.2023.05.02.13.39.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 May 2023 13:39:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) client-ip=2a03:3b40:fe:2d4::1;
Received: from meshulam.tesarici.cz (nat-97.starnet.cz [178.255.168.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id ABCCE14E38D;
	Tue,  2 May 2023 22:39:16 +0200 (CEST)
Date: Tue, 2 May 2023 22:39:15 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
 tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
 x86@kernel.org, peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH 19/40] change alloc_pages name in dma_map_ops to avoid
 name conflicts
Message-ID: <20230502223915.6b38f8c4@meshulam.tesarici.cz>
In-Reply-To: <CAJuCfpGGB204PKuqjjkPBn_XHL-xLPkn0bF6xc12Bfj8=Qzcrw@mail.gmail.com>
References: <20230501165450.15352-1-surenb@google.com>
	<20230501165450.15352-20-surenb@google.com>
	<20230502175052.43814202@meshulam.tesarici.cz>
	<CAJuCfpGSLK50eKQ2-CE41qz1oDPM6kC8RmqF=usZKwFXgTBe8g@mail.gmail.com>
	<20230502220909.3f55ae41@meshulam.tesarici.cz>
	<CAJuCfpGGB204PKuqjjkPBn_XHL-xLPkn0bF6xc12Bfj8=Qzcrw@mail.gmail.com>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.37; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=4A680Ynb;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as
 permitted sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=tesarici.cz
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

On Tue, 2 May 2023 13:24:37 -0700
Suren Baghdasaryan <surenb@google.com> wrote:

> On Tue, May 2, 2023 at 1:09=E2=80=AFPM Petr Tesa=C5=99=C3=ADk <petr@tesar=
ici.cz> wrote:
> >
> > On Tue, 2 May 2023 11:38:49 -0700
> > Suren Baghdasaryan <surenb@google.com> wrote:
> > =20
> > > On Tue, May 2, 2023 at 8:50=E2=80=AFAM Petr Tesa=C5=99=C3=ADk <petr@t=
esarici.cz> wrote: =20
> > > >
> > > > On Mon,  1 May 2023 09:54:29 -0700
> > > > Suren Baghdasaryan <surenb@google.com> wrote:
> > > > =20
> > > > > After redefining alloc_pages, all uses of that name are being rep=
laced.
> > > > > Change the conflicting names to prevent preprocessor from replaci=
ng them
> > > > > when it's not intended.
> > > > >
> > > > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > > > ---
> > > > >  arch/x86/kernel/amd_gart_64.c | 2 +-
> > > > >  drivers/iommu/dma-iommu.c     | 2 +-
> > > > >  drivers/xen/grant-dma-ops.c   | 2 +-
> > > > >  drivers/xen/swiotlb-xen.c     | 2 +-
> > > > >  include/linux/dma-map-ops.h   | 2 +-
> > > > >  kernel/dma/mapping.c          | 4 ++--
> > > > >  6 files changed, 7 insertions(+), 7 deletions(-)
> > > > >
> > > > > diff --git a/arch/x86/kernel/amd_gart_64.c b/arch/x86/kernel/amd_=
gart_64.c
> > > > > index 56a917df410d..842a0ec5eaa9 100644
> > > > > --- a/arch/x86/kernel/amd_gart_64.c
> > > > > +++ b/arch/x86/kernel/amd_gart_64.c
> > > > > @@ -676,7 +676,7 @@ static const struct dma_map_ops gart_dma_ops =
=3D {
> > > > >       .get_sgtable                    =3D dma_common_get_sgtable,
> > > > >       .dma_supported                  =3D dma_direct_supported,
> > > > >       .get_required_mask              =3D dma_direct_get_required=
_mask,
> > > > > -     .alloc_pages                    =3D dma_direct_alloc_pages,
> > > > > +     .alloc_pages_op                 =3D dma_direct_alloc_pages,
> > > > >       .free_pages                     =3D dma_direct_free_pages,
> > > > >  };
> > > > >
> > > > > diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.=
c
> > > > > index 7a9f0b0bddbd..76a9d5ca4eee 100644
> > > > > --- a/drivers/iommu/dma-iommu.c
> > > > > +++ b/drivers/iommu/dma-iommu.c
> > > > > @@ -1556,7 +1556,7 @@ static const struct dma_map_ops iommu_dma_o=
ps =3D {
> > > > >       .flags                  =3D DMA_F_PCI_P2PDMA_SUPPORTED,
> > > > >       .alloc                  =3D iommu_dma_alloc,
> > > > >       .free                   =3D iommu_dma_free,
> > > > > -     .alloc_pages            =3D dma_common_alloc_pages,
> > > > > +     .alloc_pages_op         =3D dma_common_alloc_pages,
> > > > >       .free_pages             =3D dma_common_free_pages,
> > > > >       .alloc_noncontiguous    =3D iommu_dma_alloc_noncontiguous,
> > > > >       .free_noncontiguous     =3D iommu_dma_free_noncontiguous,
> > > > > diff --git a/drivers/xen/grant-dma-ops.c b/drivers/xen/grant-dma-=
ops.c
> > > > > index 9784a77fa3c9..6c7d984f164d 100644
> > > > > --- a/drivers/xen/grant-dma-ops.c
> > > > > +++ b/drivers/xen/grant-dma-ops.c
> > > > > @@ -282,7 +282,7 @@ static int xen_grant_dma_supported(struct dev=
ice *dev, u64 mask)
> > > > >  static const struct dma_map_ops xen_grant_dma_ops =3D {
> > > > >       .alloc =3D xen_grant_dma_alloc,
> > > > >       .free =3D xen_grant_dma_free,
> > > > > -     .alloc_pages =3D xen_grant_dma_alloc_pages,
> > > > > +     .alloc_pages_op =3D xen_grant_dma_alloc_pages,
> > > > >       .free_pages =3D xen_grant_dma_free_pages,
> > > > >       .mmap =3D dma_common_mmap,
> > > > >       .get_sgtable =3D dma_common_get_sgtable,
> > > > > diff --git a/drivers/xen/swiotlb-xen.c b/drivers/xen/swiotlb-xen.=
c
> > > > > index 67aa74d20162..5ab2616153f0 100644
> > > > > --- a/drivers/xen/swiotlb-xen.c
> > > > > +++ b/drivers/xen/swiotlb-xen.c
> > > > > @@ -403,6 +403,6 @@ const struct dma_map_ops xen_swiotlb_dma_ops =
=3D {
> > > > >       .dma_supported =3D xen_swiotlb_dma_supported,
> > > > >       .mmap =3D dma_common_mmap,
> > > > >       .get_sgtable =3D dma_common_get_sgtable,
> > > > > -     .alloc_pages =3D dma_common_alloc_pages,
> > > > > +     .alloc_pages_op =3D dma_common_alloc_pages,
> > > > >       .free_pages =3D dma_common_free_pages,
> > > > >  };
> > > > > diff --git a/include/linux/dma-map-ops.h b/include/linux/dma-map-=
ops.h
> > > > > index 31f114f486c4..d741940dcb3b 100644
> > > > > --- a/include/linux/dma-map-ops.h
> > > > > +++ b/include/linux/dma-map-ops.h
> > > > > @@ -27,7 +27,7 @@ struct dma_map_ops {
> > > > >                       unsigned long attrs);
> > > > >       void (*free)(struct device *dev, size_t size, void *vaddr,
> > > > >                       dma_addr_t dma_handle, unsigned long attrs)=
;
> > > > > -     struct page *(*alloc_pages)(struct device *dev, size_t size=
,
> > > > > +     struct page *(*alloc_pages_op)(struct device *dev, size_t s=
ize,
> > > > >                       dma_addr_t *dma_handle, enum dma_data_direc=
tion dir,
> > > > >                       gfp_t gfp);
> > > > >       void (*free_pages)(struct device *dev, size_t size, struct =
page *vaddr,
> > > > > diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
> > > > > index 9a4db5cce600..fc42930af14b 100644
> > > > > --- a/kernel/dma/mapping.c
> > > > > +++ b/kernel/dma/mapping.c
> > > > > @@ -570,9 +570,9 @@ static struct page *__dma_alloc_pages(struct =
device *dev, size_t size,
> > > > >       size =3D PAGE_ALIGN(size);
> > > > >       if (dma_alloc_direct(dev, ops))
> > > > >               return dma_direct_alloc_pages(dev, size, dma_handle=
, dir, gfp);
> > > > > -     if (!ops->alloc_pages)
> > > > > +     if (!ops->alloc_pages_op)
> > > > >               return NULL;
> > > > > -     return ops->alloc_pages(dev, size, dma_handle, dir, gfp);
> > > > > +     return ops->alloc_pages_op(dev, size, dma_handle, dir, gfp)=
;
> > > > >  }
> > > > >
> > > > >  struct page *dma_alloc_pages(struct device *dev, size_t size, =
=20
> > > >
> > > > I'm not impressed. This patch increases churn for code which does n=
ot
> > > > (directly) benefit from the change, and that for limitations in you=
r
> > > > tooling?
> > > >
> > > > Why not just rename the conflicting uses in your local tree, but th=
en
> > > > remove the rename from the final patch series? =20
> > >
> > > With alloc_pages function becoming a macro, the preprocessor ends up
> > > replacing all instances of that name, even when it's not used as a
> > > function. That what necessitates this change. If there is a way to
> > > work around this issue without changing all alloc_pages() calls in th=
e
> > > source base I would love to learn it but I'm not quite clear about
> > > your suggestion and if it solves the issue. Could you please provide
> > > more details? =20
> >
> > Ah, right, I admit I did not quite understand why this change is
> > needed. However, this is exactly what I don't like about preprocessor
> > macros. Each macro effectively adds a new keyword to the language.
> >
> > I believe everything can be solved with inline functions. What exactly
> > does not work if you rename alloc_pages() to e.g. alloc_pages_caller()
> > and then add an alloc_pages() inline function which calls
> > alloc_pages_caller() with _RET_IP_ as a parameter? =20
>=20
> I don't think that would work because we need to inject the codetag at
> the file/line of the actual allocation call. If we pass _REP_IT_ then
> we would have to lookup the codetag associated with that _RET_IP_
> which results in additional runtime overhead.

OK. If the reference to source code itself must be recorded in the
kernel, and not resolved later (either by the debugfs read fops, or by
a tool which reads the file), then this information can only be
obtained with a preprocessor macro.

I was hoping that a debugging feature could be less intrusive. OTOH
it's not my call to balance the tradeoffs.

Thank you for your patient explanations.

Petr T

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230502223915.6b38f8c4%40meshulam.tesarici.cz.
