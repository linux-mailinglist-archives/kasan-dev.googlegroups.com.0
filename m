Return-Path: <kasan-dev+bncBC7OD3FKWUERBEXDYWRAMGQEHCS6QDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 7659C6F4B50
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 22:24:52 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-19297b852cfsf36102fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 13:24:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683059091; cv=pass;
        d=google.com; s=arc-20160816;
        b=TPpDJWcFxkk8LtzjOIk+ZLnSXQW/ffURwQIuU1xzt/+QMrYasfz7FujwxFvz5DzxNu
         0JtEO3FZogRgK+VtYFaClLkNA3ZF8HoWOYS6adBlIKpS65KcJogmLaF1hIuebkwm/5VL
         qWSvsoRKsFw0W13688g045obiFrVTTPVjTS0EvYZ51a01jcIIQD2EQHQeVLk7xig8CRo
         drb9xbOx+GQ16IVevyBfko6pYoXMdo0NBFWNG5Gs7qgL4t7NJjH0n4Nt7pwYrkPb8s8A
         v4gEROpuM/q65fKvZajp8YwrVupanZKIM72nn1lgxRLyTdRrqcN5dDuOCB9/jvbDbqXa
         6AGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zKTSM6eRBtqyDRRaHttBwlZhz+91OxiX0Vi8jqNDm60=;
        b=s06QjDJQe2XYKbplS3aTP89MhY6/fW8JAIs9kgy1CNdIwntMqV5EMuVxqOevu4k+ts
         rl7LxXxCOVmC4J3z7eZIT1ps87SCjPl4Re/L7G771aLxPvuUfKydOzZfIQbbfws5wXZt
         V0ol2injn6NkC+1abBAbZYdNBgjcdyg//gkDvUJrUdD4Wk+JbI3tvc6S6zB4gBMrT9NZ
         YjYO67KKVZ7UIPemTp9ql6Phr/tCgS+poB8Q4eXhIIOGzvTjZM276s3AkVy4lkdV15Aw
         tGH4cudaYjxk4w7rQei+5iXZ9aHJySt0wVF2yPbmIWtClhmxgj05BTOQF4+wqE8eUL0M
         yzbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=MU+gfSqa;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683059091; x=1685651091;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zKTSM6eRBtqyDRRaHttBwlZhz+91OxiX0Vi8jqNDm60=;
        b=eXb32jVznzkTqYK0+Ibln5JINg3ZZTPnVCPdxirSaRlbHVVlFHPQLIBBxR1qngxVNV
         0EKkmdwh3pNoq/vPtZJWD9MSRbccBiVqK8Hr5wDOTc84BNEwSkzPpOC84EpGBmgEBmka
         t8d00ZeFf5B0DAJqZnXaI47/vIS7fzX7SUolQ91RtmXmmEWaE7Wtm+CJxH/gftrJ/+VX
         y9NHDUZEtxQP/NS3df7GJaQSb4a2wsvLqPVL9j7X2wsy7z/I4G7cqp87jj29nQdtnNhQ
         ZHaMrP0Z1XMrzDvpyfglExxlGLFTRDG2NI4DdR8kEIT9QYREDEdQMmGvDsWnjZtTwwoT
         76mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683059091; x=1685651091;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zKTSM6eRBtqyDRRaHttBwlZhz+91OxiX0Vi8jqNDm60=;
        b=TMHKJTWukKZ351UlrFEY/hwYqYyRrc2fhnhwx4BjnIAvkS2ViwdLn4nuGqvUfZoysv
         WWk32yXEqv1b3NbIJ/MLfKXprlMPvqzk/wRUOyRBaFJ4YOCQuxiloYhV3Yv+4PB7MbaN
         0eD2G/hUMH/iqdHLHvmPNG700CNqCNoHj6fuxSCHAL1u+EyXXjl62okDCBxVOaGbcmWI
         2PhkbXkdAZUEMyLo5DvNIqnH4WDDV4jrYW+6jGsHAVMOzyx+nF9MdHx8wgcN+dektXx0
         oE3cRTSHO7hh6+yosbg0HIef+0bYQkCrhfHmWjLpVu6q01lgNdpQ0H94wNS9zpPOSVqy
         A7ow==
X-Gm-Message-State: AC+VfDwukdiYPqSqvWQTDF9Vur3r03omqASlah8lJ4xQWUR5q1t0+Vcm
	WgCZwePBJvwKrGNEQKxeTwI=
X-Google-Smtp-Source: ACHHUZ5vshAVD1sZzIgUoc3OU5r52u6ryhonGzccCl74KKWSTCE2xIYaEfinmHzA8yyAjCWjXFErkA==
X-Received: by 2002:a05:6808:22a2:b0:38e:8cf:b1d6 with SMTP id bo34-20020a05680822a200b0038e08cfb1d6mr8140287oib.3.1683059090922;
        Tue, 02 May 2023 13:24:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1818:b0:38d:fef4:f867 with SMTP id
 bh24-20020a056808181800b0038dfef4f867ls3543344oib.4.-pod-prod-gmail; Tue, 02
 May 2023 13:24:50 -0700 (PDT)
X-Received: by 2002:aca:1112:0:b0:38e:2567:315a with SMTP id 18-20020aca1112000000b0038e2567315amr7901392oir.1.1683059090433;
        Tue, 02 May 2023 13:24:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683059090; cv=none;
        d=google.com; s=arc-20160816;
        b=SIXIDY28URV0z1mmokWuUflDquaT1UYC9UYlm/X7/O4GgrvOvandzHDJnDFFzPHAqG
         d4ejxjiMLXrU9PhthpC2w/blrYQZy4QhvHL0kVTX99d2vI9x18zvpQ955fqRBFH7DL6L
         W3SQBSLO0WAdlGcjtwdoItYMKNCDnUqJw7HSg5HKfZeJ3BEyqGYYefTahNWBFxxI6qpQ
         76Pd23CFT/5VRMWHf55iqH45e1hDD9UtObMnJBNEefSQMPrBsFogm7dkuqJxc57/TloO
         cb+bDI7k7B7A2McWo0GCFfyi3xijYt5ajFA9VUbvsRIveFtlIgHPBRB0I8kOWWW6T8kO
         ALxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rocmb1807rrqmHexWgUhMdukatSY3k3dt0DBoDYQQ84=;
        b=IQELKeSDOf+BMeUyK228s96KbKJlPeIYSN5P5zmukt0wHBwXXQLrdOwssJnAqtXvwA
         Ytv9jNcuUsOw/sjqxHuxzoJLycSfkSa8fxjHPX2gDjECqdzWloJWkJeixXSjITnyZXNP
         coz8jUrwDTwwGPOgyWu0XQli5XAIVMQbRuQEahynZtPB/IMj+AZrgYxHO9nrTQuyU8Cq
         RKgCJxMbTDZbcGl9d6NhLwXA6zZ5Tyh/4ZjDSOp5mU9B2NNq6Fr7aDUJEDrHh7qyPLBL
         LuAD+fnOW7ZBjlAPuSB0LiNf8t/mcqsNbXKkZ/0gCXuuZdvyXvuRSED05RNikpxisclr
         z4Gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=MU+gfSqa;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id br26-20020a056830391a00b006a6203c4bc5si2545092otb.5.2023.05.02.13.24.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 May 2023 13:24:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id 3f1490d57ef6-b9a824c3a95so6132808276.1
        for <kasan-dev@googlegroups.com>; Tue, 02 May 2023 13:24:50 -0700 (PDT)
X-Received: by 2002:a25:588:0:b0:b87:d47e:9bcb with SMTP id
 130-20020a250588000000b00b87d47e9bcbmr17713528ybf.42.1683059089603; Tue, 02
 May 2023 13:24:49 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-20-surenb@google.com>
 <20230502175052.43814202@meshulam.tesarici.cz> <CAJuCfpGSLK50eKQ2-CE41qz1oDPM6kC8RmqF=usZKwFXgTBe8g@mail.gmail.com>
 <20230502220909.3f55ae41@meshulam.tesarici.cz>
In-Reply-To: <20230502220909.3f55ae41@meshulam.tesarici.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 May 2023 13:24:37 -0700
Message-ID: <CAJuCfpGGB204PKuqjjkPBn_XHL-xLPkn0bF6xc12Bfj8=Qzcrw@mail.gmail.com>
Subject: Re: [PATCH 19/40] change alloc_pages name in dma_map_ops to avoid
 name conflicts
To: =?UTF-8?B?UGV0ciBUZXNhxZnDrWs=?= <petr@tesarici.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=MU+gfSqa;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Tue, May 2, 2023 at 1:09=E2=80=AFPM Petr Tesa=C5=99=C3=ADk <petr@tesaric=
i.cz> wrote:
>
> On Tue, 2 May 2023 11:38:49 -0700
> Suren Baghdasaryan <surenb@google.com> wrote:
>
> > On Tue, May 2, 2023 at 8:50=E2=80=AFAM Petr Tesa=C5=99=C3=ADk <petr@tes=
arici.cz> wrote:
> > >
> > > On Mon,  1 May 2023 09:54:29 -0700
> > > Suren Baghdasaryan <surenb@google.com> wrote:
> > >
> > > > After redefining alloc_pages, all uses of that name are being repla=
ced.
> > > > Change the conflicting names to prevent preprocessor from replacing=
 them
> > > > when it's not intended.
> > > >
> > > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > > ---
> > > >  arch/x86/kernel/amd_gart_64.c | 2 +-
> > > >  drivers/iommu/dma-iommu.c     | 2 +-
> > > >  drivers/xen/grant-dma-ops.c   | 2 +-
> > > >  drivers/xen/swiotlb-xen.c     | 2 +-
> > > >  include/linux/dma-map-ops.h   | 2 +-
> > > >  kernel/dma/mapping.c          | 4 ++--
> > > >  6 files changed, 7 insertions(+), 7 deletions(-)
> > > >
> > > > diff --git a/arch/x86/kernel/amd_gart_64.c b/arch/x86/kernel/amd_ga=
rt_64.c
> > > > index 56a917df410d..842a0ec5eaa9 100644
> > > > --- a/arch/x86/kernel/amd_gart_64.c
> > > > +++ b/arch/x86/kernel/amd_gart_64.c
> > > > @@ -676,7 +676,7 @@ static const struct dma_map_ops gart_dma_ops =
=3D {
> > > >       .get_sgtable                    =3D dma_common_get_sgtable,
> > > >       .dma_supported                  =3D dma_direct_supported,
> > > >       .get_required_mask              =3D dma_direct_get_required_m=
ask,
> > > > -     .alloc_pages                    =3D dma_direct_alloc_pages,
> > > > +     .alloc_pages_op                 =3D dma_direct_alloc_pages,
> > > >       .free_pages                     =3D dma_direct_free_pages,
> > > >  };
> > > >
> > > > diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
> > > > index 7a9f0b0bddbd..76a9d5ca4eee 100644
> > > > --- a/drivers/iommu/dma-iommu.c
> > > > +++ b/drivers/iommu/dma-iommu.c
> > > > @@ -1556,7 +1556,7 @@ static const struct dma_map_ops iommu_dma_ops=
 =3D {
> > > >       .flags                  =3D DMA_F_PCI_P2PDMA_SUPPORTED,
> > > >       .alloc                  =3D iommu_dma_alloc,
> > > >       .free                   =3D iommu_dma_free,
> > > > -     .alloc_pages            =3D dma_common_alloc_pages,
> > > > +     .alloc_pages_op         =3D dma_common_alloc_pages,
> > > >       .free_pages             =3D dma_common_free_pages,
> > > >       .alloc_noncontiguous    =3D iommu_dma_alloc_noncontiguous,
> > > >       .free_noncontiguous     =3D iommu_dma_free_noncontiguous,
> > > > diff --git a/drivers/xen/grant-dma-ops.c b/drivers/xen/grant-dma-op=
s.c
> > > > index 9784a77fa3c9..6c7d984f164d 100644
> > > > --- a/drivers/xen/grant-dma-ops.c
> > > > +++ b/drivers/xen/grant-dma-ops.c
> > > > @@ -282,7 +282,7 @@ static int xen_grant_dma_supported(struct devic=
e *dev, u64 mask)
> > > >  static const struct dma_map_ops xen_grant_dma_ops =3D {
> > > >       .alloc =3D xen_grant_dma_alloc,
> > > >       .free =3D xen_grant_dma_free,
> > > > -     .alloc_pages =3D xen_grant_dma_alloc_pages,
> > > > +     .alloc_pages_op =3D xen_grant_dma_alloc_pages,
> > > >       .free_pages =3D xen_grant_dma_free_pages,
> > > >       .mmap =3D dma_common_mmap,
> > > >       .get_sgtable =3D dma_common_get_sgtable,
> > > > diff --git a/drivers/xen/swiotlb-xen.c b/drivers/xen/swiotlb-xen.c
> > > > index 67aa74d20162..5ab2616153f0 100644
> > > > --- a/drivers/xen/swiotlb-xen.c
> > > > +++ b/drivers/xen/swiotlb-xen.c
> > > > @@ -403,6 +403,6 @@ const struct dma_map_ops xen_swiotlb_dma_ops =
=3D {
> > > >       .dma_supported =3D xen_swiotlb_dma_supported,
> > > >       .mmap =3D dma_common_mmap,
> > > >       .get_sgtable =3D dma_common_get_sgtable,
> > > > -     .alloc_pages =3D dma_common_alloc_pages,
> > > > +     .alloc_pages_op =3D dma_common_alloc_pages,
> > > >       .free_pages =3D dma_common_free_pages,
> > > >  };
> > > > diff --git a/include/linux/dma-map-ops.h b/include/linux/dma-map-op=
s.h
> > > > index 31f114f486c4..d741940dcb3b 100644
> > > > --- a/include/linux/dma-map-ops.h
> > > > +++ b/include/linux/dma-map-ops.h
> > > > @@ -27,7 +27,7 @@ struct dma_map_ops {
> > > >                       unsigned long attrs);
> > > >       void (*free)(struct device *dev, size_t size, void *vaddr,
> > > >                       dma_addr_t dma_handle, unsigned long attrs);
> > > > -     struct page *(*alloc_pages)(struct device *dev, size_t size,
> > > > +     struct page *(*alloc_pages_op)(struct device *dev, size_t siz=
e,
> > > >                       dma_addr_t *dma_handle, enum dma_data_directi=
on dir,
> > > >                       gfp_t gfp);
> > > >       void (*free_pages)(struct device *dev, size_t size, struct pa=
ge *vaddr,
> > > > diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
> > > > index 9a4db5cce600..fc42930af14b 100644
> > > > --- a/kernel/dma/mapping.c
> > > > +++ b/kernel/dma/mapping.c
> > > > @@ -570,9 +570,9 @@ static struct page *__dma_alloc_pages(struct de=
vice *dev, size_t size,
> > > >       size =3D PAGE_ALIGN(size);
> > > >       if (dma_alloc_direct(dev, ops))
> > > >               return dma_direct_alloc_pages(dev, size, dma_handle, =
dir, gfp);
> > > > -     if (!ops->alloc_pages)
> > > > +     if (!ops->alloc_pages_op)
> > > >               return NULL;
> > > > -     return ops->alloc_pages(dev, size, dma_handle, dir, gfp);
> > > > +     return ops->alloc_pages_op(dev, size, dma_handle, dir, gfp);
> > > >  }
> > > >
> > > >  struct page *dma_alloc_pages(struct device *dev, size_t size,
> > >
> > > I'm not impressed. This patch increases churn for code which does not
> > > (directly) benefit from the change, and that for limitations in your
> > > tooling?
> > >
> > > Why not just rename the conflicting uses in your local tree, but then
> > > remove the rename from the final patch series?
> >
> > With alloc_pages function becoming a macro, the preprocessor ends up
> > replacing all instances of that name, even when it's not used as a
> > function. That what necessitates this change. If there is a way to
> > work around this issue without changing all alloc_pages() calls in the
> > source base I would love to learn it but I'm not quite clear about
> > your suggestion and if it solves the issue. Could you please provide
> > more details?
>
> Ah, right, I admit I did not quite understand why this change is
> needed. However, this is exactly what I don't like about preprocessor
> macros. Each macro effectively adds a new keyword to the language.
>
> I believe everything can be solved with inline functions. What exactly
> does not work if you rename alloc_pages() to e.g. alloc_pages_caller()
> and then add an alloc_pages() inline function which calls
> alloc_pages_caller() with _RET_IP_ as a parameter?

I don't think that would work because we need to inject the codetag at
the file/line of the actual allocation call. If we pass _REP_IT_ then
we would have to lookup the codetag associated with that _RET_IP_
which results in additional runtime overhead.

>
> Petr T
>
> --
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kernel-team+unsubscribe@android.com.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGGB204PKuqjjkPBn_XHL-xLPkn0bF6xc12Bfj8%3DQzcrw%40mail.gmai=
l.com.
